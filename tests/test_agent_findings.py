import json
from pathlib import Path

import pytest
from test_providers import endpoint
from textual.widgets import DataTable, TextArea

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings, tool_findings
from argo.context_budget import ModelLimits
from argo.evidence import EvidenceStore, read_state, verify
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
