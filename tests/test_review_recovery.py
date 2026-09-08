import json
from pathlib import Path

import httpx
import pytest
from test_providers import endpoint

from argo.agent import run_agent
from argo.agent_models import ANALYST, LocalModelError, review
from argo.controller import Cancelled
from argo.evidence import read_evidence, verify


def sources(body):
    return json.loads(body['messages'][-1]['content'])


def answer(body, truncated=False):
    result = {'summary': 'Reviewed supplied source', 'suspected_findings': []}
    return [{'message': {'content': json.dumps(result)}, 'done': True, 'done_reason': 'length' if truncated else 'stop'}]


def test_split_retry_preserves_every_character_and_does_not_repeat_completed_files(monkeypatch):
    files = {f'part_{index}.ts': f'const section = {index};\n' * 80 for index in range(3)}

    def chunks(body):
        current = sources(body)
        return answer(body, truncated=len(current) > 1)

    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        result = review(ANALYST, files)
    requests = [r['body'] for r in records if r['path'] == '/api/chat']
    successful = [sources(body) for body in requests if len(sources(body)) == 1]
    assert len(successful) == 3
    assert {path: source for batch in successful for path, source in batch.items()} == files
    assert result['source_batches'] == 3
    assert result['completed_paths'] == sorted(files)
    assert result['unreviewed_paths'] == []
    assert [retry['split_depth'] for retry in result['review_retries']] == [1, 2]


def test_single_file_split_carries_line_ranges_and_reconstructs_original_source(monkeypatch):
    source = ''.join(f'const value_{index} = {index};\n' for index in range(100))

    def chunks(body):
        return answer(body, truncated=len(sources(body)['app.ts']) > len(source) // 2 + 30)

    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        result = review(ANALYST, {'app.ts': source})
    requests = [r['body'] for r in records if r['path'] == '/api/chat']
    assert len(requests) == 4
    assert ''.join(sources(body)['app.ts'] for body in requests[2:]) == source
    assert result['completed_paths'] == ['app.ts']
    first, second = result['reviewed_segments']
    assert first['ranges']['app.ts'][0] == 0
    assert first['ranges']['app.ts'][1] == second['ranges']['app.ts'][0]
    assert second['ranges']['app.ts'][1] == len(source)
    metadata = [json.loads(body['messages'][1]['content'].split('\n', 1)[1]) for body in requests[2:]]
    assert metadata[0]['app.ts']['partial_file'] is True
    assert metadata[1]['app.ts']['start_line'] == sources(requests[2])['app.ts'].count('\n') + 1


def test_permanent_truncation_stops_at_bounded_split_depth(monkeypatch):
    statuses = []
    with endpoint('ollama', chunks=lambda body: answer(body, truncated=True)) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        with pytest.raises(LocalModelError, match='8,192') as raised:
            review(ANALYST, {'app.ts': 'const value = 1;\n' * 400}, on_status=statuses.append)
    assert len([r for r in records if r['path'] == '/api/chat']) == 6
    assert raised.value.partial_review['completed_paths'] == []
    assert raised.value.partial_review['unreviewed_paths'] == ['app.ts']
    assert len(raised.value.partial_review['review_retries']) == 2
    assert any('split 2/2' in status for status in statuses)


@pytest.mark.parametrize('failure', ['transport', 503, 401])
def test_transient_request_retries_once_without_replaying_successful_source(monkeypatch, failure):
    calls, statuses = [], []

    def structured(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            request = httpx.Request('POST', 'http://127.0.0.1/api/chat')
            if failure == 'transport':
                raise httpx.ReadError('private transport detail', request=request)
            raise httpx.HTTPStatusError('private provider detail', request=request, response=httpx.Response(failure, request=request))
        return {'summary': 'Recovered', 'suspected_findings': []}

    monkeypatch.setattr('argo.agent_models.structured', structured)
    if failure == 401:
        with pytest.raises(LocalModelError) as raised:
            review(ANALYST, {'app.ts': 'const value = 1'}, on_status=statuses.append)
        assert 'private provider' not in str(raised.value)
        assert len(calls) == 1
    else:
        assert review(ANALYST, {'app.ts': 'const value = 1'}, on_status=statuses.append)['summary'] == 'Recovered'
        assert len(calls) == 2 and any('retrying once' in value for value in statuses)


def test_cancellation_stops_before_split_retry(monkeypatch):
    stopped = False

    def status(value):
        nonlocal stopped
        stopped = 'smaller source batches' in value

    def check():
        if stopped:
            raise Cancelled('Stop before recovery request')

    with endpoint('ollama', chunks=lambda body: answer(body, truncated=True)) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        with pytest.raises(Cancelled):
            review(ANALYST, {'app.ts': 'const value = 1;\n' * 100}, check, on_status=status)
    assert len([r for r in records if r['path'] == '/api/chat']) == 2


@pytest.mark.live
def test_controller_persists_partial_review_without_accepting_missing_coverage(tmp_path, monkeypatch):
    def chunks(body):
        current = sources(body)
        if len(current) > 1 or 'bad.ts' in current:
            return answer(body, truncated=True)
        result = {'summary': 'Reviewed first file', 'suspected_findings': [{'path': 'good.ts', 'issue': 'Synthetic observation', 'remediation': 'Validate independently'}]}
        return [{'message': {'content': json.dumps(result)}, 'done': True, 'done_reason': 'stop'}]

    actions = [
        {'action': 'security.review', 'parameters': {'model': 'foundation', 'paths': ['good.ts', 'bad.ts']}},
        {'action': 'finish', 'parameters': {'summary': 'Must not count the failed review as complete'}},
    ]
    with endpoint('ollama', chunks=chunks) as (local, _), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        output = run_agent('Review both files', tmp_path, seed={'good.ts': 'const good = 1;', 'bad.ts': 'const bad = 2;'}, coding=coding, use_mcp=False, required_reviews=(ANALYST,), max_steps=2)
    assert output['status'] == 'incomplete'
    path = Path(output['report']).parent
    report = json.loads((path / 'report.json').read_text())
    stored = read_evidence(path, report['tools'][0]['evidence_id'])['data']['result']
    assert stored['status'] == 'failed'
    assert stored['completed_paths'] == ['good.ts'] and stored['unreviewed_paths'] == ['bad.ts']
    assert len(stored['reviewed_segments']) == 1
    assert report['findings'][0]['status'] == 'suspected'
    assert verify(path)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.parametrize('edit', [False, True])
def test_redacted_export_only_blocks_completion_when_workspace_changed(tmp_path, edit):
    project = tmp_path / 'project'
    project.mkdir()
    original = 'const password = "synthetic-password";\n'
    (project / 'config.js').write_text(original)
    actions = []
    if edit:
        actions.extend([
            {'action': 'code.edit', 'parameters': {'paths': ['config.js'], 'instruction': 'Add a constant without changing the existing fixture'}},
            {'files': [{'path': 'config.js', 'content': original + 'const updated = true;\n'}]},
        ])
    actions.append({'action': 'finish', 'parameters': {'summary': 'Finished requested fixture task'}})
    with endpoint('openai', replies=actions) as (coding, _):
        output = run_agent('Review fixture' if not edit else 'Update fixture', tmp_path / 'runs', project=project, coding=coding, use_mcp=False, max_steps=2 if edit else 1)
    assert output['status'] == ('incomplete' if edit else 'complete')
    path = Path(output['report']).parent
    assert 'synthetic-password' not in (path / 'code/config.js').read_text()
    assert (project / 'config.js').read_text() == original + ('const updated = true;\n' if edit else '')
    assert verify(path)['status'] == 'verified'
