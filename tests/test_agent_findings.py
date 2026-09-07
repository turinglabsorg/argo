import asyncio
import json
import threading
from pathlib import Path

import pytest
from test_providers import endpoint
from textual.widgets import DataTable, TextArea

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings, tool_findings
from argo.agent_models import QWEN, REVIEWER, SPECIALISTS
from argo.context_budget import ModelLimits
from argo.evidence import EvidenceStore, read_evidence, read_state, verify
from argo.tui import ArgoApp


def legacy_run(root):
    store = EvidenceStore(root, 'legacy-audit', 'a' * 64, 4)
    identity = store.add('agent_tool', {
        'action': {'tool': 'python.run', 'arguments': {'path': 'verify.py'}},
        'result': {'exit_code': 0, 'stdout': json.dumps({'findings': [
            {'id': 'AS-01', 'titolo': 'Missing ownership check', 'file': 'app.py', 'verdict': 'sfruttabile', 'evidenza': 'A static match only', 'status': 'confirmed', 'evidence_ids': ['f' * 64]},
        ]})},
    })
    report = {'kind': 'isolated_agent', 'project': '/untrusted/report/path', 'summary': 'One static observation', 'findings': [], 'tools': [{'tool': 'python.run', 'evidence_id': identity}]}
    (store.path / 'report.json').write_text(json.dumps(report))
    store.set('finding_count', 0)
    store.manifest()
    store.close()
    return store.path, report, identity


def test_legacy_findings_use_verified_records_not_model_verdicts(tmp_path):
    path, report, identity = legacy_run(tmp_path)
    findings = load_agent_findings(path, report)
    assert len(findings) == 1
    assert findings[0]['status'] == 'suspected'
    assert findings[0]['severity'] == 'info'
    assert findings[0]['evidence_ids'] == [identity]
    assert 'static' in findings[0]['explanation']
    target = path / 'evidence' / (identity + '.json')
    target.write_text('{}')
    with pytest.raises(ValueError, match='integrity'):
        load_agent_findings(path, report)


def test_plain_prose_and_invalid_paths_do_not_become_findings():
    assert tool_findings({'action': {'tool': 'python.run'}, 'result': {'exit_code': 0, 'stdout': 'There is a vulnerability'}}, 'a' * 64) == []
    assert tool_findings({'action': {'tool': 'security.review'}, 'result': {'suspected_findings': [{'path': '../outside', 'issue': 'Unsafe'}]}}, 'a' * 64) == []


@pytest.mark.live
@pytest.mark.parametrize('invalid', [None, 'evidence', 'path'])
def test_record_findings_over_http_persists_reports_and_live_progress(tmp_path, invalid):
    calls = 0
    def respond(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {'action': 'workspace.read', 'parameters': {'path': 'app.py'}}
        if calls == 2:
            observed = next(json.loads(message['content'].split('\n', 1)[1]) for message in body['messages'] if message['content'].startswith('Observed tool result'))
            item = {'title': 'Ownership check missing', 'path': 'absent.py' if invalid == 'path' else 'app.py', 'severity': 'high', 'explanation': 'Read route has no ownership guard', 'remediation': 'Check ownership', 'evidence_ids': ['f' * 64 if invalid == 'evidence' else observed['evidence_id']]}
            return {'action': 'findings.record', 'parameters': {'findings': [item]}}
        return {'action': 'finish', 'parameters': {'summary': 'Review finished'}}
    progress = []
    with endpoint('openai', replies=respond) as (profile, _):
        result = run_agent('Review source without edits', tmp_path, seed={'app.py': 'value = 1'}, coding=profile, use_mcp=False, max_steps=3, on_progress=progress.append)
    path = Path(result['report']).parent
    report = json.loads((path / 'report.json').read_text())
    expected = 0 if invalid else 1
    assert len(report['findings']) == result['findings'] == read_state(path)['finding_count'] == expected
    assert bool([event for event in progress if event.get('findings')]) == (not invalid)
    if not invalid:
        assert report['findings'][0]['status'] == 'suspected'
        assert 'Ownership check missing' in (path / 'report.md').read_text()
    assert verify(path)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.parametrize('model', ['qwen', 'unconfigured'])
def test_third_reviewer_routes_over_http_and_persists_suspected_findings(tmp_path, monkeypatch, model):
    calls = []

    def local_reply(body):
        calls.append(body)
        return {'summary': 'Ownership must be checked', 'suspected_findings': [{'path': 'app.py', 'issue': 'Missing ownership check', 'remediation': 'Verify the owner'}]}

    actions = [{'action': 'security.review', 'parameters': {'model': model, 'paths': ['app.py']}}, {'action': 'finish', 'parameters': {'summary': 'Review complete'}}]
    with endpoint('ollama', replies=local_reply) as (local, _), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Review using Qwen, without edits', tmp_path, seed={'app.py': 'value = 1'}, coding=coding, use_mcp=False, max_steps=2)
    path = Path(result['report']).parent
    report = json.loads((path / 'report.json').read_text())
    assert QWEN in report['models']['security']
    if model == 'qwen':
        assert len(calls) == 1 and calls[0]['model'] == QWEN
        assert len(report['findings']) == 1
        assert report['findings'][0]['status'] == 'suspected'
        assert report['tools'][0]['model'] == QWEN
    else:
        assert calls == [] and report['findings'] == []
    assert verify(path)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.parametrize('failed', [False, True])
def test_parallel_review_saves_independent_evidence_and_coverage_gaps(tmp_path, monkeypatch, failed):
    barrier = threading.Barrier(3, timeout=3)

    def chunks(body):
        barrier.wait()
        if failed and body['model'] == REVIEWER:
            yield {'error': 'Private internal failure'}
            return
        result = {'summary': 'Review complete', 'suspected_findings': [{'path': 'app.py', 'issue': 'Observation from ' + body['model'], 'remediation': 'Verify ownership'}]}
        yield {'message': {'content': json.dumps(result)}, 'done': True}

    actions = [{'action': 'security.review_all', 'parameters': {'paths': ['app.py']}}, {'action': 'finish', 'parameters': {'summary': 'Compared reviewer responses'}}]
    with endpoint('ollama', chunks=chunks) as (local, _), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Review with all three models concurrently', tmp_path, seed={'app.py': 'value = 1'}, coding=coding, use_mcp=False, max_steps=2)
    path = Path(result['report']).parent
    report = json.loads((path / 'report.json').read_text())
    individual = [r for r in report['tools'] if r['tool'] == 'security.review']
    assert {r['model'] for r in individual} == set(SPECIALISTS.values())
    assert len(report['findings']) == (2 if failed else 3)
    assert len(report['coverage_gaps']) == (1 if failed else 0)
    assert all(f['status'] == 'suspected' for f in report['findings'])
    assert {f['evidence_ids'][0] for f in report['findings']} <= {r['evidence_id'] for r in individual}
    assert verify(path)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.asyncio
async def test_failed_single_review_is_recorded_and_restored(tmp_path, monkeypatch):
    calls = []

    def chunks(body):
        calls.append(body)
        yield {'error': 'Private internal failure'}

    actions = [{'action': 'security.review', 'parameters': {'model': 'qwen', 'paths': ['app.py']}}, {'action': 'finish', 'parameters': {'summary': 'Specialist unavailable'}}]
    with endpoint('ollama', chunks=chunks) as (local, _), endpoint('openai', replies=actions) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = await asyncio.to_thread(run_agent, 'Review source without edits', tmp_path / 'runs', seed={'app.py': 'value = 1'}, coding=coding, use_mcp=False, max_steps=2)
    assert len(calls) == 1 and calls[0]['model'] == QWEN
    path = Path(result['report']).parent
    report = json.loads((path / 'report.json').read_text())
    event = report['tools'][0]
    assert event['tool'] == 'security.review' and event['model'] == QWEN
    assert event['status'] == 'failed'
    saved = read_evidence(path, event['evidence_id'])['data']['result']
    assert saved['error'] and 'Private internal failure' not in str(saved)
    assert report['findings'] == [] and len(report['coverage_gaps']) == 1
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'local_models': []}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits())
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=(80, 24)):
        app.resume(path.name)
        assert app.model_activity[QWEN]['state'] == 'Error'
        assert app.model_activity[QWEN]['text'] == saved['error']
    assert verify(path)['status'] == 'verified'


@pytest.mark.asyncio
async def test_legacy_specialist_gap_restores_error_without_changing_report(tmp_path, monkeypatch):
    path, report, _ = legacy_run(tmp_path / 'runs')
    report['coverage_gaps'] = [QWEN + ': Local review exceeded its deadline.']
    original = json.dumps(report)
    (path / 'report.json').write_text(original)
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'local_models': []}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits())
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=(80, 24)):
        app.resume(path.name)
        assert app.model_activity[QWEN]['state'] == 'Error'
        assert 'exceeded its deadline' in app.model_activity[QWEN]['text']
    assert (path / 'report.json').read_text() == original


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(80, 24), (140, 44)])
async def test_reopen_legacy_run_populates_findings_and_count(tmp_path, monkeypatch, size):
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'status': 'unavailable', 'local_models': []}})
    monkeypatch.setattr('argo.tui.model_limits', lambda *_: ModelLimits())
    path, report, identity = legacy_run(tmp_path / 'runs')
    app = ArgoApp(tmp_path / 'runs', project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.resume(path.name)
        await pilot.pause()
        assert app.project is None
        assert app.query_one('#findings', DataTable).row_count == 1
        assert 'suspected' in str(app.query_one('#findings', DataTable).get_row_at(0))
        assert identity in app.query_one('#finding-detail', TextArea).text
        assert app.query_one('#runs', DataTable).get_row_at(0)[3].plain == '1'
        findings = load_agent_findings(path, report)
        app.progress({'run_id': path.name, 'stage': 'findings', 'findings': findings * 1})
        assert app.query_one('#findings', DataTable).row_count == 1
