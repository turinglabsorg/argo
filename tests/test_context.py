import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_providers import SCHEMA, endpoint

from argo.agent import run_agent
from argo.context_budget import ModelLimits, estimate_tokens
from argo.controller import Cancelled
from argo.conversation import Conversation
from argo.evidence import read_evidence, verify
from argo.providers import ProviderResponseError, generate, model_limits


@pytest.mark.parametrize('window,output', [(1048576, 943718), (32768, 8192)])
def test_api_limits_control_input_and_output(window, output):
    metadata = {'context_length': window, 'top_provider': {'context_length': window, 'max_completion_tokens': output}}
    with endpoint('openai', metadata=metadata) as (profile, records):
        limits = model_limits(profile)
        assert limits.context_window == window
        assert limits.max_output_tokens == output
        messages = [{'role': 'user', 'content': 'source line\n' * 5000}]
        assert generate(profile, messages, SCHEMA) == {'ok': True}
        assert records[-1]['body']['max_tokens'] == limits.initial_output(messages, SCHEMA)
        assert sum(row['method'] == 'GET' for row in records) == 1
        if window > 1000000:
            assert records[-1]['body']['max_tokens'] > 32768
            assert limits.output_budget([], SCHEMA) > 900000
            assert limits.input_budget > 800000


def test_unknown_endpoint_limits_are_explicit_and_overridable():
    with endpoint('anthropic') as (profile, _):
        limits = model_limits(profile)
        assert 'Fallback' in limits.source
        assert limits.context_window == 16384
        profile = profile.model_copy(update={'context_window': 100000, 'max_tokens': 2048})
        limits = model_limits(profile)
        assert limits.context_window == 100000
        assert limits.output_budget([], SCHEMA, profile.max_tokens) == 2048
    with endpoint('openai', status=401) as (profile, _):
        assert 'Fallback' in model_limits(profile).source
        with pytest.raises(RuntimeError, match='HTTP 401'):
            generate(profile, [], SCHEMA)


def test_truncation_retries_only_generation_and_respects_explicit_cap():
    with endpoint('openai', reasoning_tokens=4096, metadata={'context_length': 64000, 'max_output_tokens': 10000}) as (profile, records):
        assert generate(profile, [], SCHEMA, tokens=1024) == {'ok': True}
        assert [row['body']['max_tokens'] for row in records if row['method'] == 'POST'] == [1024, 4096]
        capped = profile.model_copy(update={'max_tokens': 2048})
        with pytest.raises(ProviderResponseError, match='truncated'):
            generate(capped, [], SCHEMA)
        assert records[-1]['body']['max_tokens'] == 2048


@pytest.mark.parametrize('reply,reasoning,expected', [({'ok': True}, 99999, 'output_limit'), ({'wrong': 'synthetic-fixture-key'}, 0, 'invalid_schema')])
def test_authenticated_child_keeps_safe_error_classification(reply, reasoning, expected):
    with endpoint('openai', replies=[reply], reasoning_tokens=reasoning) as (profile, _):
        payload = {'profile': profile.model_dump(), 'operation': 'generate', 'messages': [], 'schema': SCHEMA, 'tokens': 2048}
        result = subprocess.run([sys.executable, '-I', '-m', 'argo.provider_worker'], input=json.dumps(payload), text=True, capture_output=True, timeout=10, env={**os.environ, 'ARGO_PROVIDER_KEY': 'synthetic-fixture-key'})
        assert result.returncode == 0
        assert json.loads(result.stdout)['code'] == expected
        assert 'synthetic-fixture-key' not in result.stdout + result.stderr


def test_large_model_retains_history_without_fixed_turn_or_character_cutoff():
    conversation = Conversation(ModelLimits(context_window=1048576, max_output_tokens=943718))
    conversation.observations.extend({'evidence_id': str(i), 'untrusted_result': 'A' * 10000} for i in range(20))
    opening = [{'role': 'user', 'content': 'Keep original task'}]
    messages = conversation.prepare(opening, {'role': 'user', 'content': 'Next action'}, lambda *_: pytest.fail('Unnecessary compaction'))
    assert len(messages) == 22
    assert '"evidence_id": "0"' in messages[1]['content']
    assert conversation.compactions == 0


def test_auto_compact_uses_http_summary_and_retains_recent_results():
    with endpoint('openai', replies=[{'summary': 'Changed app.py. Pytest passed. Inspect remaining issue E1.'}] * 10, metadata={'context_length': 16384, 'max_output_tokens': 4096}) as (profile, records):
        conversation = Conversation(model_limits(profile))
        conversation.observations.extend([{'evidence_id': 'E1', 'untrusted_result': 'old result ' * 4000}, {'evidence_id': 'E2', 'untrusted_result': 'latest pytest passed'}])
        events = []
        opening = [{'role': 'user', 'content': 'Original operator task and authorization constraints'}]
        closing = {'role': 'user', 'content': 'Continue from completed tools'}
        messages = conversation.prepare(opening, closing, lambda messages, schema: generate(profile, messages, schema), on_compact=events.append)
        assert messages[0] == opening[0] and messages[-1] == closing
        assert 'Changed app.py' in messages[1]['content']
        assert any('latest pytest passed' in message['content'] for message in messages)
        assert estimate_tokens(messages) < conversation.limits.input_budget
        assert conversation.compactions == 1
        assert events[-1]['phase'] == 'complete'
        assert events[-1]['after_tokens'] < events[-1]['before_tokens']
        assert all('summary' in row['body']['messages'][0]['content'] for row in records if row['method'] == 'POST')


def test_compact_failure_and_cancellation_preserve_history():
    for exception in (ProviderResponseError('invalid_json'), Cancelled('Cancelled')):
        conversation = Conversation(ModelLimits())
        original = {'untrusted_result': 'x' * 70000}
        conversation.observations.append(original)
        def fail(*_):
            raise exception
        with pytest.raises(type(exception)):
            conversation.prepare([], {'role': 'user', 'content': 'Next'}, fail)
        assert conversation.observations == [original]
        assert conversation.summary == ''
        assert conversation.compactions == 0


@pytest.mark.live
def test_large_selected_file_reaches_coder_and_write_runs_once(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    original = 'Original source notes.\n' * 2000
    (project / 'notes.txt').write_text(original)
    replies = [
        {'action': 'code.edit', 'parameters': {'paths': ['notes.txt'], 'instruction': 'Replace notes with the reviewed summary'}},
        {'files': [{'path': 'notes.txt', 'content': 'Reviewed summary.\n'}]},
        {'action': 'finish', 'parameters': {'summary': 'Updated notes, no executable code changed.'}},
    ]
    with endpoint('openai', replies=replies, metadata={'context_length': 1048576, 'max_output_tokens': 943718}) as (profile, records):
        result = run_agent('Review and update notes', tmp_path / 'runs', coding=profile, project=project, use_mcp=False)
    assert result['status'] == 'complete', result
    assert (project / 'notes.txt').read_text() == 'Reviewed summary.\n'
    generations = [row for row in records if row['method'] == 'POST']
    assert len(generations) == 3
    source = json.loads(generations[1]['body']['messages'][-1]['content'])['workspace']['notes.txt']
    assert source == original
    assert verify(Path(result['report']).parent)['status'] == 'verified'


@pytest.mark.live
def test_agent_persists_auto_compact_without_repeating_tools(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    for name in ('notes1.txt', 'notes2.txt'):
        (project / name).write_text('Original source notes.\n' * 3000)
    calls = {'actions': 0, 'summaries': 0}
    def reply(body):
        if body['messages'][1]['content'].startswith('Summarize an ongoing'):
            calls['summaries'] += 1
            return {'summary': 'Read notes.txt. Evidence exists; no files changed. Finish the requested review.'}
        calls['actions'] += 1
        return {'action': 'workspace.read', 'parameters': {'path': f"notes{calls['actions']}.txt"}} if calls['actions'] <= 2 else {'action': 'finish', 'parameters': {'summary': 'Reviewed notes. No code edits were needed.'}}
    with endpoint('openai', replies=reply, metadata={'context_length': 16384, 'max_output_tokens': 4096}) as (profile, _):
        result = run_agent('Review notes.txt', tmp_path / 'runs', coding=profile, project=project, use_mcp=False)
    assert result['status'] == 'complete', result
    run = Path(result['report']).parent
    report = json.loads((run / 'report.json').read_text())
    assert len(report['tools']) == 2
    assert calls['actions'] == 3 and calls['summaries'] >= 2
    assert len(report['context_compactions']) == 2
    saved = json.loads((run / 'context.json').read_text())
    assert saved['operator_task'] == 'Review notes.txt'
    assert saved['compactions'] == 2
    assert (run / 'context.json').stat().st_mode & 0o777 == 0o600
    evidence = read_evidence(run, report['context_compactions'][-1])
    assert evidence['data']['summary'] == saved['summary']
    assert verify(run)['status'] == 'verified'


def test_rate_limit_error_preserves_upstream_source_without_body_disclosure():
    error = {'message': 'synthetic-private-message', 'metadata': {'raw': 'synthetic-private-body', 'limit_source': 'upstream_provider_shared_pool', 'retry_after_seconds': 60}}
    with endpoint('openai', status=429, error=error) as (profile, _):
        payload = {'profile': profile.model_dump(), 'operation': 'generate', 'messages': [], 'schema': SCHEMA}
        result = subprocess.run([sys.executable, '-I', '-m', 'argo.provider_worker'], input=json.dumps(payload), text=True, capture_output=True, timeout=10, env={**os.environ, 'ARGO_PROVIDER_KEY': 'synthetic-fixture-key'})
        data = json.loads(result.stdout)
        assert data['status'] == 429
        assert data['retry_after'] == 60 and data['shared_pool'] is True
        assert 'shared provider pool' in data['error']
        assert 'synthetic-private' not in result.stdout


def test_dynamic_output_grows_to_model_ceiling_when_needed():
    with endpoint('openai', reasoning_tokens=200000, metadata={'context_length': 1048576, 'max_output_tokens': 943718}) as (profile, records):
        assert generate(profile, [], SCHEMA) == {'ok': True}
        outputs = [row['body']['max_tokens'] for row in records if row['method'] == 'POST']
        assert outputs == [32768, 131072, 524288]
        assert model_limits(profile).context_window == 1048576


def test_compact_does_not_drop_history_when_checkpoint_cannot_be_saved():
    conversation = Conversation(ModelLimits())
    conversation.observations.append({'untrusted_result': 'x' * 50000})
    original = list(conversation.observations)
    def checkpoint(event):
        if event['phase'] == 'complete':
            raise OSError('Cannot save checkpoint')
    with pytest.raises(OSError):
        conversation.prepare([], {'role': 'user', 'content': 'Next'}, lambda *_: {'summary': 'Reviewed prior tool evidence.'}, on_compact=checkpoint)
    assert conversation.observations == original
    assert conversation.summary == '' and conversation.compactions == 0
