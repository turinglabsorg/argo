import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_providers import endpoint

from argo.agent import run_agent
from argo.agent_models import ANALYST, QWEN, REVIEWER, LocalModelError, review, review_limits
from argo.controller import Cancelled
from argo.evidence import read_evidence, verify


@pytest.mark.parametrize('model,elapsed,accepted', [
    (ANALYST, 310, True),
    (ANALYST, 1190, True),
    (ANALYST, 1201, False),
    (REVIEWER, 301, False),
    (QWEN, 1201, True),
])
def test_review_deadline_allows_slow_foundation_but_remains_bounded(monkeypatch, model, elapsed, accepted):
    clock = SimpleNamespace(value=10.0)
    monkeypatch.setattr('argo.agent_models.time', SimpleNamespace(monotonic=lambda: clock.value))
    final = {'summary': 'Reviewed', 'suspected_findings': []}
    chunks = [{'message': {'thinking': 'Checking ownership'}, 'done': False},
              {'message': {'content': json.dumps(final)}, 'done': True, 'done_reason': 'stop'}]

    def progress(_):
        clock.value = 10.0 + elapsed

    with endpoint('ollama', chunks=chunks) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        if accepted:
            assert review(model, {'app.py': 'value = 1'}, on_reasoning=progress)['summary'] == 'Reviewed'
        else:
            with pytest.raises(LocalModelError, match='deadline'):
                review(model, {'app.py': 'value = 1'}, on_reasoning=progress)
    requests = [r['body'] for r in records if r['path'] == '/api/chat']
    assert len(requests) == 1
    assert requests[0]['options']['num_ctx'] == review_limits(model).context_window


def test_foundation_can_still_be_cancelled_after_the_old_deadline(monkeypatch):
    clock = SimpleNamespace(value=10.0)
    monkeypatch.setattr('argo.agent_models.time', SimpleNamespace(monotonic=lambda: clock.value))

    def progress(_):
        clock.value += 310

    def check():
        if clock.value > 300:
            raise Cancelled('Operator stopped review')

    with endpoint('ollama', chunks=[{'message': {'thinking': 'Checking source'}, 'done': False}]) as (profile, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        with pytest.raises(Cancelled, match='Operator stopped'):
            review(ANALYST, {'app.py': 'value = 1'}, check, on_reasoning=progress)


@pytest.mark.live
def test_long_foundation_review_completes_through_controller_and_saves_evidence(tmp_path, monkeypatch):
    clock = SimpleNamespace(value=10.0)
    monkeypatch.setattr('argo.agent.time', SimpleNamespace(monotonic=lambda: clock.value))

    def response(_):
        clock.value += 1900
        return {'summary': 'Reviewed source', 'suspected_findings': []}

    actions = [
        {'action': 'security.review', 'parameters': {'model': 'foundation', 'paths': ['app.py']}},
        {'action': 'finish', 'parameters': {'summary': 'Review complete'}},
    ]
    with endpoint('ollama', replies=response) as (local, _), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Review source without edits', tmp_path, seed={'app.py': 'value = 1'},
                           coding=coding, use_mcp=False, required_reviews=(ANALYST,), max_steps=2)
    assert result['status'] == 'complete'
    path = Path(result['report']).parent
    report = json.loads((path / 'report.json').read_text())
    assert report['coverage_gaps'] == []
    saved = read_evidence(path, report['tools'][0]['evidence_id'])['data']['result']
    assert saved['model'] == ANALYST and saved['summary'] == 'Reviewed source'
    assert verify(path)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.parametrize('required,elapsed,accepted,mode', [
    ((ANALYST,), 2200, True, 'offline'),
    ((QWEN,), 2200, True, 'offline'),
    ((QWEN,), 14401, False, 'offline'),
    ((), 2200, False, 'offline'),
    ((), 2200, True, 'connected'),
    ((), 14401, False, 'connected'),
])
def test_required_review_budget_covers_source_reading_before_inference(tmp_path, monkeypatch, required, elapsed, accepted, mode):
    clock = SimpleNamespace(value=10.0)
    monkeypatch.setattr('argo.agent.time', SimpleNamespace(monotonic=lambda: clock.value))

    def progress(event):
        if event['stage'] == 'workspace.read':
            clock.value = 10.0 + elapsed

    actions = [{'action': 'workspace.read', 'parameters': {'path': 'app.py'}}]
    if required:
        actions.append({'action': 'security.review', 'parameters': {
            'model': 'qwen' if required[0] == QWEN else 'foundation', 'paths': ['app.py'],
        }})
    actions.append({'action': 'finish', 'parameters': {'summary': 'The owned source was read and reviewed.'}})
    with endpoint('ollama', replies=[{'summary': 'Reviewed', 'suspected_findings': []}]) as (local, records), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Audit source after a long initial inventory', tmp_path, seed={'app.py': 'value = 1'},
                           coding=coding, use_mcp=False, required_reviews=required, max_steps=4, on_progress=progress,
                           intelligence_mode=mode)
    assert result['status'] == ('complete' if accepted else 'failed')
    if not accepted:
        assert result['summary'] == 'Agent task deadline exceeded'
    assert len([record for record in records if record['path'] == '/api/chat']) == int(accepted and bool(required))
    assert verify(Path(result['report']).parent)['status'] == 'verified'
