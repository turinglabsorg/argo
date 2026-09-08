import copy
import json
from pathlib import Path

import pytest
from test_finding_validation import finding, fixture
from test_providers import endpoint
from textual.widgets import DataTable, TextArea

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings
from argo.agent_models import edit
from argo.contracts import Finding
from argo.evidence import verify
from argo.finding_validation import (
    apply_result,
    check_verification_edit,
    description,
    invalidate,
    run_tests,
    verdict,
)
from argo.tui import ArgoApp
from argo.workspace import Workspace


@pytest.mark.live
@pytest.mark.parametrize('limit', ['deadline', 'output'])
def test_finding_execution_limits_preserve_evidence_and_worker(limit):
    path = 'tests/argo-security/limited.test.cjs'
    valid = "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('actual control', () => assert.equal(1 + 1, 2));\n"
    extra = "setInterval(() => {}, 1000);\n" if limit == 'deadline' else "console.log('x'.repeat(300000));\n"
    with Workspace() as workspace:
        workspace.call('write', files={path: valid + extra})
        result = workspace.call('finding_test', path=path)
        assert result['outcome'] == 'inconclusive'
        assert result['exit_code'] == 124
        assert result['execution_limit'] == limit
        assert result['stdout'] and len(result['stdout']) <= 128 * 1024
        assert workspace.active
        workspace.call('write', files={path: valid})
        assert workspace.call('finding_test', path=path)['outcome'] == 'passed'


@pytest.mark.live
def test_controller_persists_complete_repair_and_rejects_premature_finish(tmp_path, monkeypatch):
    source, tests, paths = fixture()
    fixed, _, _ = fixture(vulnerable=False)
    calls, current = 0, {}

    def progress(event):
        if event.get('findings'):
            current.update(event['findings'][0])

    def reply(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {'action': 'workspace.read', 'parameters': {'path': 'access.py'}}
        if calls == 2:
            observation = json.loads(body['messages'][-2]['content'].split('\n', 1)[1])
            return {'action': 'findings.record', 'parameters': {'findings': [{'path': 'access.py', 'title': 'Cross-owner access', 'severity': 'high', 'explanation': 'Cross-owner input may be accepted', 'remediation': 'Enforce ownership', 'evidence_ids': [observation['evidence_id']]}]}}
        if calls == 3:
            return {'action': 'code.edit', 'parameters': {'paths': list(tests), 'instruction': 'Write the original regression and both controls'}}
        if calls == 4:
            return {'files': [{'path': path, 'content': text} for path, text in tests.items()]}
        if calls in (5, 10):
            return {'action': 'findings.test', 'parameters': {'finding_id': current['id'], 'hypothesis': 'Cross-owner access', 'expected_secure_behavior': 'Reject another owner', 'source_paths': ['access.py'], 'tests': paths}}
        if calls in (6, 11):
            return {'action': 'findings.verdict', 'parameters': {'finding_id': current['id'], 'test_evidence_id': current['verification']['test_evidence_id'], 'interpretation': 'reproduced' if calls == 6 else 'fixed', 'explanation': 'Observed regression and control outcomes'}}
        if calls == 7:
            assert assessment['test_assessment'] in json.dumps(body['messages'])
            return {'action': 'code.edit', 'parameters': {'paths': ['access.py'], 'instruction': 'Enforce ownership while retaining all original tests'}}
        if calls == 8:
            return {'files': [{'path': path, 'content': text} for path, text in fixed.items()]}
        if calls == 9:
            return {'action': 'finish', 'parameters': {'summary': 'Premature fix claim'}}
        if calls == 12:
            return {'action': 'python.tests', 'parameters': {}}
        return {'action': 'finish', 'parameters': {'summary': 'Reproduced, fixed and retested with unchanged tests'}}

    assessment = {'decision': 'agree', 'summary': 'The real ownership tests support this scoped verdict', 'test_assessment': 'Both controls cover valid and absent identities; regression exercises cross-owner input', 'remaining_concerns': []}
    with endpoint('ollama', replies=lambda _: assessment) as (local, requests), endpoint('openai', replies=reply, metadata={'context_length': 131072}) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Reproduce and fix cross-owner access', tmp_path / 'runs', seed=source, coding=coding, use_mcp=False, max_steps=14, on_progress=progress)
    assert result['status'] == 'complete', result
    root = Path(result['report']).parent
    report = json.loads((root / 'report.json').read_text())
    item = report['findings'][0]
    assert item['verification']['state'] == 'fixed'
    reviews = item['verification']['reviews']
    assert [entry['phase'] for entry in reviews] == ['finding', 'fix']
    prompts = [json.loads(request['body']['messages'][-1]['content']) for request in requests if request['path'] == '/api/chat']
    assert len(prompts) == 2
    assert prompts[0]['files']['access.py'] == source['access.py']
    assert prompts[1]['files']['access.py'] == fixed['access.py']
    assert prompts[1]['before']['files'] == prompts[0]['files']
    assert prompts[0]['runtime']['test_hashes'] == prompts[1]['runtime']['test_hashes']
    assert prompts[1]['before']['runtime']['cases']['regression']['outcome'] == 'assertion_failed'
    assert prompts[1]['runtime']['cases']['regression']['outcome'] == 'passed'
    assert 'Private scratchpad' not in (root / 'report.json').read_text()
    assert item['verification']['reproduction']['test_evidence_id'] != item['verification']['test_evidence_id']
    assert load_agent_findings(root, {**report, 'findings': []})[0]['verification'] == item['verification']
    assert verify(root)['status'] == 'verified'
    assert all((root / 'code' / path).read_text() == text for path, text in tests.items())
    assert (root / 'code/access.py').read_text() == fixed['access.py']


@pytest.mark.live
@pytest.mark.parametrize('language', ['python', 'node'])
def test_failing_then_passing_unchanged_controls_establish_verified_fix(language):
    source, tests, paths = fixture(language)
    asset = next(iter(source))
    item = finding(asset)
    args = {'finding_id': item['id'], 'hypothesis': 'Cross-owner access', 'expected_secure_behavior': 'Reject another owner', 'source_paths': [asset], 'tests': paths}
    helper = {'tests/support.txt': 'Original test support'}
    with Workspace() as workspace:
        workspace.call('write', files={**source, **tests, **helper})
        before = run_tests(workspace, item, args, lambda *_: 'a' * 64)
        apply_result(item, 'findings.test', before, 'b' * 64)
        reproduced = verdict(item, {'finding_id': item['id'], 'test_evidence_id': 'b' * 64, 'interpretation': 'reproduced', 'explanation': 'Regression failed and controls passed'}, before)
        apply_result(item, 'findings.verdict', reproduced, 'c' * 64)
        baseline = copy.deepcopy(item['verification']['reproduction'])
        assert baseline['test_evidence_id'] == 'b' * 64
        for path in [paths['regression'], 'tests/support.txt']:
            with pytest.raises(ValueError, match='locked'):
                check_verification_edit([item], [path])
        check_verification_edit([item], [asset])
        fixed_source, _, _ = fixture(language, vulnerable=False)
        workspace.call('write', files=fixed_source)
        assert invalidate([item], workspace.call('export')['files'], {})
        assert item['verification']['state'] == 'stale'
        after = run_tests(workspace, item, args, lambda *_: 'd' * 64)
        apply_result(item, 'findings.test', after, 'e' * 64)
        assert item['verification']['reproduction'] == baseline
        base = {'finding_id': item['id'], 'test_evidence_id': 'e' * 64, 'explanation': 'Same regression and controls pass after the implementation change'}
        with pytest.raises(ValueError, match='cannot be relabeled refuted'):
            verdict(item, {**base, 'interpretation': 'refuted'}, after)
        result = verdict(item, {**base, 'interpretation': 'fixed'}, after)
        apply_result(item, 'findings.verdict', result, 'f' * 64)
        assert item['verification']['state'] == 'fixed'
        assert item['verification']['reproduction'] == baseline
        assert Finding.model_validate(item).verification.state == 'fixed'
        assert before['cases']['regression']['outcome'] == 'assertion_failed'
        assert after['cases']['regression']['outcome'] == 'passed'
        assert before['test_hashes'] == after['test_hashes']
        assert 'Original failing test evidence: ' + 'b' * 64 in description(item)
        for corruption in ['no_baseline', 'no_source_change', 'changed_tests', 'changed_helper', 'failed_control', 'wrong_roles']:
            candidate, record = copy.deepcopy(item), copy.deepcopy(after)
            if corruption == 'no_baseline':
                candidate['verification']['reproduction'] = None
            elif corruption == 'no_source_change':
                record['source_hashes'] = baseline['source_hashes']
            elif corruption == 'changed_tests':
                record['test_hashes'][paths['regression']] = '0' * 64
            elif corruption == 'changed_helper':
                record['support_hashes']['tests/support.txt'] = '0' * 64
            elif corruption == 'failed_control':
                record['cases']['positive_control']['outcome'] = 'assertion_failed'
            else:
                record['tests']['regression'] = paths['positive_control']
            with pytest.raises(ValueError):
                verdict(candidate, {**base, 'interpretation': 'fixed'}, record)
        workspace.call('write', files={'tests/support.txt': 'Changed helper'})
        with pytest.raises(ValueError, match='helpers changed'):
            run_tests(workspace, item, args, lambda *_: '0' * 64)
        workspace.call('write', files=helper)
        workspace.call('write', files={'tests/conftest.py': '# New setup file\n'})
        with pytest.raises(ValueError, match='New test helpers'):
            run_tests(workspace, item, args, lambda *_: '0' * 64)
        assert invalidate([item], {**source, **tests, **helper}, {})
        assert item['verification']['state'] == 'stale'


@pytest.mark.live
@pytest.mark.parametrize('report,exit_code,output_size,expected', [
    ({'success': True, 'numTotalTests': 2, 'numPassedTests': 2, 'numFailedTests': 0, 'numPendingTests': 0}, 0, 0, 'passed'),
    ({'success': True, 'numTotalTests': 0, 'numPassedTests': 0, 'numFailedTests': 0, 'numPendingTests': 0}, 0, 0, 'inconclusive'),
    ({'success': True, 'numTotalTests': 2, 'numPassedTests': 1, 'numFailedTests': 0, 'numPendingTests': 1}, 0, 0, 'inconclusive'),
    ({'success': False, 'numTotalTests': 2, 'numPassedTests': 1, 'numFailedTests': 1, 'numPendingTests': 0, 'testResults': [{'name': '/workspace/tests/owned.test.ts', 'status': 'failed', 'assertionResults': [{'status': 'failed', 'fullName': 'Rejects foreign ownership', 'failureMessages': ['Expected denial, received success']}]}]}, 1, 0, 'inconclusive'),
    ({'success': True, 'numTotalTests': 2, 'numPassedTests': 2, 'numFailedTests': 0, 'numPendingTests': 0}, 0, 300000, 'inconclusive'),
])
def test_project_runner_contract_uses_fixed_command_and_requires_nonempty_success(report, exit_code, output_size, expected):
    source = "import fs from 'node:fs';\nimport assert from 'node:assert/strict';\nassert.deepEqual(process.argv.slice(2, 6), ['run', '--maxWorkers=1', '--no-file-parallelism', '--reporter=json']);\nconst target = process.argv.find(arg => arg.startsWith('--outputFile=')).slice(13);\n" + 'fs.writeFileSync(target, JSON.stringify(' + json.dumps(report) + '));\nfs.writeSync(1, "x".repeat(' + str(output_size) + '));\nprocess.exit(' + str(exit_code) + ');\n'
    with Workspace() as workspace:
        with pytest.raises(ValueError):
            workspace.call('project_tests', runner='vitest')
        workspace.call('write', files={'node_modules/vitest/vitest.mjs': source})
        result = workspace.call('project_tests', runner='vitest')
        assert result['outcome'] == expected, result
        assert result['workspace_unchanged']
        if output_size:
            assert result['execution_limit'] == 'output'
            assert result['exit_code'] == 124
        if exit_code:
            assert result['failures'] == [{'path': 'tests/owned.test.ts', 'test': 'Rejects foreign ownership', 'message': 'Expected denial, received success'}]
        with pytest.raises(ValueError, match='Supported project runner'):
            workspace.call('project_tests', runner='arbitrary-shell')


@pytest.mark.live
@pytest.mark.parametrize('successful', [True, False])
def test_project_suite_failure_blocks_completion_of_an_edit(tmp_path, successful):
    project = tmp_path / 'project'
    entrypoint = project / 'node_modules/vitest/vitest.mjs'
    entrypoint.parent.mkdir(parents=True)
    counts = {'success': successful, 'numTotalTests': 1, 'numPassedTests': int(successful), 'numFailedTests': int(not successful), 'numPendingTests': 0}
    entrypoint.write_text("import fs from 'node:fs'; fs.writeFileSync(process.argv.find(arg => arg.startsWith('--outputFile=')).slice(13), JSON.stringify(" + json.dumps(counts) + ")); process.exit(" + str(int(not successful)) + ");")
    (project / 'app.js').write_text('module.exports = false;\n')
    decisions = [
        {'action': 'code.edit', 'parameters': {'paths': ['app.js'], 'instruction': 'Export true'}},
        {'files': [{'path': 'app.js', 'content': 'module.exports = true;\n'}]},
        {'action': 'project.tests', 'parameters': {'runner': 'vitest'}},
        {'action': 'finish', 'parameters': {'summary': 'Edited and tested'}},
    ]
    with endpoint('openai', replies=decisions, metadata={'context_length': 131072}) as (coding, _):
        result = run_agent('Edit and run the installed suite', tmp_path / 'runs', coding=coding, project=project, use_mcp=False, max_steps=3)
    assert result['status'] == ('complete' if successful else 'incomplete'), result


@pytest.mark.live
def test_project_runner_detects_changes_to_oversized_lockfile():
    report = {'success': True, 'numTotalTests': 1, 'numPassedTests': 1, 'numFailedTests': 0, 'numPendingTests': 0}
    source = "import fs from 'node:fs'; fs.writeFileSync('yarn.lock', '# changed\\n'.repeat(10000)); fs.writeFileSync(process.argv.find(arg => arg.startsWith('--outputFile=')).slice(13), JSON.stringify(" + json.dumps(report) + '));'
    with Workspace() as workspace:
        workspace.call('write', files={'prepare.py': "from pathlib import Path\nPath('yarn.lock').write_text('# original\\n' * 10000)\n", 'node_modules/vitest/vitest.mjs': source})
        assert workspace.call('python', path='prepare.py')['exit_code'] == 0
        result = workspace.call('project_tests', runner='vitest')
        assert result['outcome'] == 'inconclusive'
        assert not result['workspace_unchanged']


@pytest.mark.asyncio
@pytest.mark.parametrize('size', [(80, 24), (140, 44)])
async def test_tui_displays_fixed_state_and_original_reproduction(tmp_path, monkeypatch, size):
    monkeypatch.setattr('argo.tui.doctor', lambda: {'ollama': {'local_models': []}})
    item = finding('access.py')
    item['verification'].update(state='fixed', test_evidence_id='b' * 64, reproduction={'test_evidence_id': 'a' * 64, 'verdict_evidence_id': 'c' * 64})
    item['verification']['reviews'] = [{'phase': phase, 'decision': 'agree', 'test_evidence_id': identity * 64, 'summary': 'Controls and source reviewed', 'evidence_id': evidence * 64} for phase, identity, evidence in [('finding', 'a', 'd'), ('fix', 'b', 'e')]]
    app = ArgoApp(tmp_path, project=None, settings_path=tmp_path / 'models.json')
    async with app.run_test(size=size) as pilot:
        app.report_data = {'kind': 'isolated_agent', 'findings': [item]}
        app.refresh_findings()
        await pilot.pause()
        assert 'fixed' in str(app.query_one('#findings', DataTable).get_row_at(0))
        details = app.query_one('#finding-detail', TextArea).text
        assert 'Runtime verification: fixed' in details
        assert 'Original failing test evidence: ' + 'a' * 64 in details
        assert 'Qwen · finding review · agree · historical' in details
        assert 'Qwen · fix review · agree' in details
        assert 'Review evidence: ' + 'e' * 64 in details


@pytest.mark.live
@pytest.mark.parametrize('invalid', [
    "'use strict'; // Everything else was flattened into this comment: test('ignored', () => assert.ok(false));",
    "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('incomplete', () => assert.ok(true));\nprocess.exit(0);\n",
    "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('broken', () => { assert.ok(true);\n",
])
def test_coder_repairs_nonexecuting_or_invalid_node_tests_before_write(invalid):
    path = 'tests/argo-security/control.test.cjs'
    valid = "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('control', () => assert.ok(true));\n"
    replies = [{'files': [{'path': path, 'content': content}]} for content in (invalid, valid)]
    with Workspace() as workspace, endpoint('openai', replies=replies, metadata={'context_length': 131072}) as (coding, requests):
        result = edit('Create a Node control', [path], {}, profile=coding, validate_code=lambda values: workspace.call('validate_code', files=values))
        assert result[path] == valid
        assert workspace.call('export')['files'] == {}
        assert len([r for r in requests if r['method'] == 'POST']) == 2
        workspace.call('write', files=result)
        assert workspace.call('finding_test', path=path)['outcome'] == 'passed'


@pytest.mark.live
def test_javascript_syntax_validation_never_executes_source():
    with Workspace() as workspace:
        result = workspace.call('validate_code', files={'code.cjs': "require('node:fs').writeFileSync('/workspace/should-not-exist.txt', 'not executed');"})
        assert result['syntax_checked'] == ['code.cjs']
        assert workspace.call('export')['files'] == {}


@pytest.mark.live
def test_coder_line_arrays_preserve_executable_multiline_source():
    path = 'tests/argo-security/lines.test.cjs'
    lines = ["const test = require('node:test');", "const assert = require('node:assert/strict');", "// This comment must not swallow the following test.", "test('multiline output', () => {", "  assert.equal(1 + 1, 2);", "});"]
    reply = {'files': [{'path': path, 'lines': lines}]}
    with Workspace() as workspace, endpoint('openai', replies=[reply], metadata={'context_length': 131072}) as (coding, _):
        result = edit('Create a control with line-array output', [path], {}, profile=coding, validate_code=lambda values: workspace.call('validate_code', files=values))
        assert result[path] == '\n'.join(lines) + '\n'
        workspace.call('write', files=result)
        assert workspace.call('finding_test', path=path)['outcome'] == 'passed'


@pytest.mark.live
@pytest.mark.parametrize('body,expected', [
    ("describe('audit',()=>{it('anonymous',()=>assert.equal(1,2));it('user',()=>assert.equal(1,2));});", 'assertion_failed'),
    ("test('parent',async t=>{await t.test('child',()=>assert.equal(1,2));});", 'assertion_failed'),
    ("test('wrapped exception',()=>assert.doesNotThrow(()=>{throw new RangeError('invalid input');}));", 'assertion_failed'),
    ("test('wrapped rejection',async()=>assert.doesNotReject(async()=>{throw new TypeError('invalid input');}));", 'assertion_failed'),
    ("test('runtime with assertion cause',()=>{try{assert.equal(1,2);}catch(cause){throw new Error('fixture failure',{cause});}});", 'inconclusive'),
    ("test('wrapped exception',()=>assert.doesNotThrow(()=>{throw new RangeError('invalid input');}));test('runtime',()=>{throw new Error('fixture failure');});", 'inconclusive'),
    ("describe('audit',()=>{it('assertion',()=>assert.equal(1,2));it('runtime',()=>{throw new Error('fixture unavailable');});});", 'inconclusive'),
    ("describe('audit',()=>{before(()=>{throw new Error('setup');});it('unreached',()=>assert.equal(1,2));});", 'inconclusive'),
])
def test_nested_node_assertions_are_distinct_from_runtime_and_setup_errors(body, expected):
    source = "const {test,describe,it,before}=require('node:test');\nconst assert=require('node:assert/strict');\n" + body
    with Workspace() as workspace:
        workspace.call('write', files={'tests/argo-security/nested.test.cjs': source})
        result = workspace.call('finding_test', path='tests/argo-security/nested.test.cjs')
        assert result['outcome'] == expected, result


@pytest.mark.live
def test_explicit_coding_context_preserves_model_capacity_and_runs_the_edit(tmp_path):
    calls = 0
    marker = 'UNRELATED_CONTEXT_MARKER'
    def reply(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {'action': 'code.edit', 'parameters': {'paths': ['app.js'], 'context_paths': ['helper.js'], 'instruction': 'Use the existing helper export'}}
        if calls == 2:
            prompt = json.dumps(body['messages'])
            assert marker not in prompt
            assert 'module.exports = 7;' in prompt
            return {'files': [{'path': 'app.js', 'content': "module.exports = require('./helper.js');\n"}]}
        if calls == 3:
            return {'action': 'node.tests', 'parameters': {}}
        return {'action': 'finish', 'parameters': {'summary': 'Updated with focused context and executed the result'}}
    seed = {'app.js': 'module.exports = 0;\n', 'helper.js': 'module.exports = 7;\n', 'unrelated.txt': marker, 'tests/argo-security/app.test.cjs': "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('uses helper', () => assert.equal(require('../../app.js'), 7));\n"}
    with endpoint('openai', replies=reply, metadata={'context_length': 1048576}) as (coding, _):
        result = run_agent('Use the existing helper export and run its test', tmp_path / 'runs', seed=seed, coding=coding, use_mcp=False, max_steps=3)
    assert result['status'] == 'complete', result
    assert calls == 4
