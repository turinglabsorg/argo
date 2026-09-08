import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from test_providers import SCHEMA, endpoint

from argo import providers
from argo.agent import run_agent
from argo.evidence import read_evidence, verify
from argo.provider_usage import capture_usage, summarize_usage
from argo.providers import CodingProfile, ProviderResponseError, exchange, generate, request

USAGE = {'prompt_tokens': 1000, 'completion_tokens': 7, 'cost': 0.002, 'prompt_tokens_details': {'cached_tokens': 800, 'cache_write_tokens': 0}}


@pytest.mark.parametrize('stream', [True, False])
def test_usage_survives_real_http_and_missing_counters_are_unknown(stream):
    events = []
    with endpoint('openai', json_response=not stream, usage=USAGE) as (profile, _):
        assert generate(profile, [], SCHEMA, on_usage=events.append) == {'ok': True}
    assert len(events) == 1
    assert events[0]['cached_tokens'] == 800
    assert events[0]['prompt_tokens'] == 1000
    assert events[0]['cost_usd'] == 0.002
    assert events[0]['response_complete']
    with endpoint('openai', json_response=not stream) as (profile, _):
        generate(profile, [], SCHEMA, on_usage=events.append)
    totals = summarize_usage(events)
    assert totals['responses'] == 2
    assert totals['cache_measured_responses'] == 1
    assert totals['cache_hit_ratio'] == 0.8
    assert summarize_usage([events[-1]])['cached_tokens'] is None


def test_openrouter_final_usage_chunk_and_origin_scoped_session(monkeypatch):
    requests, events = [], []

    def respond(incoming):
        requests.append(incoming)
        if incoming.method == 'GET':
            return httpx.Response(200, json={'data': []})
        chunks = [
            {'id': 'gen-fixture', 'provider': 'Fixture', 'choices': [{'delta': {'content': '{"ok":true}'}, 'finish_reason': 'stop'}]},
            {'id': 'gen-fixture', 'choices': [], 'usage': USAGE},
        ]
        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=''.join('data: ' + json.dumps(chunk) + '\n\n' for chunk in chunks) + 'data: [DONE]\n\n')

    client = httpx.Client
    monkeypatch.setattr(providers.httpx, 'Client', lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    for base in ('https://openrouter.ai/api/v1', 'https://openrouter.ai:443/api/v1', 'https://api.openai.com/v1', 'https://openrouter.ai.example.org/v1', 'http://openrouter.ai/api/v1', 'https://openrouter.ai:8443/api/v1'):
        profile = CodingProfile(protocol='openai', base_url=base)
        exchange(profile, 'models', session_id='argo-fixture-coordination')
        assert 'x-session-id' not in requests[-1].headers
        assert exchange(profile, 'generate', [], SCHEMA, session_id='argo-fixture-coordination', on_usage=events.append) == {'ok': True}
        allowed = base in ('https://openrouter.ai/api/v1', 'https://openrouter.ai:443/api/v1')
        assert ('x-session-id' in requests[-1].headers) == allowed
        assert ('stream_options' in json.loads(requests[-1].content)) == allowed
        assert events[-1]['generation_id'] == 'gen-fixture'
        assert events[-1]['cached_tokens'] == 800
    assert len(events) == 6
    with pytest.raises(ValueError, match='session identifier'):
        exchange(CodingProfile(protocol='openai', base_url='https://openrouter.ai/api/v1'), 'generate', [], SCHEMA, session_id='bad\nheader')


def test_anthropic_cache_counts_are_part_of_total_input_and_not_double_counted():
    record = {}
    capture_usage(record, {'type': 'message_start', 'message': {'usage': {'input_tokens': 100, 'cache_read_input_tokens': 800, 'cache_creation_input_tokens': 100, 'output_tokens': 1}}}, 'anthropic')
    capture_usage(record, {'type': 'message_delta', 'usage': {'output_tokens': 7}}, 'anthropic')
    assert record['prompt_tokens'] == 1000
    assert record['completion_tokens'] == 7
    assert summarize_usage([record])['cache_hit_ratio'] == 0.8
    capture_usage(record, {'usage': {'prompt_tokens': True, 'cost': float('nan'), 'prompt_tokens_details': {'cached_tokens': -1}}}, 'openai')
    assert record['prompt_tokens'] == 1000 and record['cached_tokens'] == 800
    assert 'cost_usd' not in record
    assert summarize_usage([{'prompt_tokens': 10, 'cached_tokens': 11}])['cache_hit_ratio'] is None


@pytest.mark.parametrize('invalid', [False, True])
def test_credential_child_preserves_usage_on_success_and_invalid_answer(invalid):
    with endpoint('openai', usage=USAGE, replies=[{'wrong': True} if invalid else {'ok': True}]) as (profile, _):
        payload = {'profile': profile.model_dump(), 'operation': 'generate', 'messages': [], 'schema': SCHEMA, 'session_id': 'argo-fixture-coding'}
        result = subprocess.run([sys.executable, '-I', '-m', 'argo.provider_worker'], input=json.dumps(payload), text=True, capture_output=True, timeout=10, env={**os.environ, 'ARGO_PROVIDER_KEY': 'synthetic-fixture-key'})
    assert result.returncode == 0
    reply = json.loads(result.stdout)
    assert reply['usage'][0]['cached_tokens'] == 800
    assert reply['usage'][0]['response_complete'] is not invalid
    assert 'synthetic-fixture-key' not in result.stdout + result.stderr
    if invalid:
        assert reply['code'] == 'invalid_schema'


def test_hush_parent_forwards_session_and_observes_usage_before_error(monkeypatch, tmp_path):
    binary = tmp_path / 'hush'
    binary.touch()
    monkeypatch.setattr(providers.shutil, 'which', lambda _: str(binary))
    events = []

    def command(args, timeout, check, stdin):
        assert json.loads(stdin)['session_id'] == 'argo-fixture-coding'
        assert '--redact' in args
        return 0, json.dumps({'code': 'output_limit', 'error': 'truncated', 'usage': [{'cached_tokens': 800, 'prompt_tokens': 1000}]}).encode(), b''

    monkeypatch.setattr(providers, 'command', command)
    with pytest.raises(ProviderResponseError, match='truncated'):
        request(CodingProfile(credential='fixture'), 'generate', [], SCHEMA, session_id='argo-fixture-coding', on_usage=events.append)
    assert events == [{'cached_tokens': 800, 'prompt_tokens': 1000}]


def test_retry_reuses_session_and_preserves_each_attempt_usage(monkeypatch):
    events = []
    sessions = []
    original_request = providers.request

    def observe(profile, operation, *args, **kwargs):
        if operation == 'generate':
            sessions.append(kwargs['session_id'])
        return original_request(profile, operation, *args, **kwargs)

    monkeypatch.setattr(providers, 'request', observe)
    with endpoint('openai', usage=USAGE, reasoning_tokens=4096, metadata={'context_length': 64000, 'max_output_tokens': 10000}) as (profile, _):
        generate(profile, [], SCHEMA, tokens=1024, session_id='argo-fixture-coordination', on_usage=events.append)
    assert len(events) == 2
    assert sessions == ['argo-fixture-coordination'] * 2
    assert not events[0]['response_complete'] and events[1]['response_complete']
    assert summarize_usage(events)['measured_prompt_tokens'] == 2000


@pytest.mark.live
def test_agent_persists_usage_without_putting_metrics_in_model_context(tmp_path, monkeypatch):
    original_request = providers.request
    sessions = []

    def observe(profile, operation, *args, **kwargs):
        if operation == 'generate':
            sessions.append(kwargs['session_id'])
        return original_request(profile, operation, *args, **kwargs)

    monkeypatch.setattr(providers, 'request', observe)
    replies = [
        {'action': 'workspace.read', 'parameters': {'path': 'notes.txt'}},
        {'action': 'finish', 'parameters': {'summary': 'Read the notes. No changes.'}},
    ]
    with endpoint('openai', replies=replies, usage=USAGE) as (profile, requests):
        result = run_agent('Read notes.txt and finish.', tmp_path / 'runs', seed={'notes.txt': 'Synthetic fixture'}, coding=profile, use_mcp=False)
    assert result['status'] == 'complete', result
    root = Path(result['report']).parent
    report = json.loads((root / 'report.json').read_text())
    assert sessions == [f"argo-{result['run_id']}-coordination"] * 2
    assert report['usage_summary']['cache_hit_ratio'] == 0.8
    assert report['usage_summary']['responses'] == 2
    assert len(report['provider_usage']) == 2
    assert read_evidence(root, report['provider_usage'][0])['data']['operation'] == 'coordination'
    assert verify(root)['status'] == 'verified'
    assert '80.0%' in Path(result['report']).read_text()
    bodies = [request['body'] for request in requests if request['method'] == 'POST']
    assert bodies[0]['messages'][:3] == bodies[1]['messages'][:3]
    assert all('cached_tokens' not in json.dumps(body['messages']) for body in bodies)
