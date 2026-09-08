import json
from pathlib import Path

import pytest
from test_finding_validation import fixture
from test_providers import endpoint

from argo.agent import run_agent
from argo.evidence import read_evidence, verify


def controller_status(body):
    return json.loads(body['messages'][-1]['content'].split('Controller status:\n')[1])


def latest_observation(body):
    return json.loads(body['messages'][-2]['content'].split('\n', 1)[1])


def observation(title, evidence):
    return {'path': 'access.cjs', 'title': title, 'severity': 'info', 'explanation': title, 'remediation': 'Verify the actual behavior', 'evidence_ids': [evidence]}


@pytest.mark.live
@pytest.mark.parametrize('runtime_error', [False, True])
def test_verdict_recovery_uses_current_evidence_and_prioritizes_inflight_finding(tmp_path, monkeypatch, runtime_error):
    source, tests, paths = fixture('node')
    if runtime_error:
        tests[paths['regression']] += "test('unavailable fixture',()=>{throw new Error('fixture unavailable');});\n"
    calls, selected, first, source_evidence, test_evidence = 0, None, None, None, None

    def reply(body):
        nonlocal calls, selected, first, source_evidence, test_evidence
        if any(message['content'].startswith('Summarize an ongoing') for message in body['messages']):
            return {'summary': 'Two findings are registered. One has current runtime tests. Use the controller status and recovery guidance for exact IDs and allowed interpretations; no verdict is established yet.'}
        calls += 1
        status = controller_status(body)
        if calls == 1:
            return {'action': 'workspace.read', 'parameters': {'path': 'access.cjs'}}
        if calls == 2:
            source_evidence = latest_observation(body)['evidence_id']
            return {'action': 'findings.record', 'parameters': {'findings': [observation('Separate unavailable scenario', source_evidence), observation('Cross-owner access', source_evidence)]}}
        if calls == 3:
            first, selected = [item['id'] for item in status['finding_verification']['items']]
            return {'action': 'findings.test', 'parameters': {'finding_id': selected, 'hypothesis': 'Cross-owner access', 'expected_secure_behavior': 'Reject another owner', 'source_paths': ['access.cjs'], 'tests': paths}}
        if calls == 4:
            active = status['next_finding_verification']
            assert active['finding_id'] == selected
            test_evidence = active['latest_test_evidence_id']
            visible = json.loads(latest_observation(body)['untrusted_result'])
            assert visible['verdict_guidance']['latest_test_evidence_id'] == test_evidence
            assert 'source_hashes' not in visible and 'support_hashes' not in visible
            assert all('source_hashes' not in case for case in visible['cases'].values())
            assert visible['test_hashes'] and visible['cases']['regression']['stdout']
            return {'action': 'findings.verdict', 'parameters': {'finding_id': selected, 'test_evidence_id': '0' * 64, 'interpretation': 'refuted', 'explanation': 'Incorrect evidence must be rejected'}}
        if calls in (5, 6):
            feedback = latest_observation(body)
            guidance = feedback['verification_recovery']
            assert guidance['finding_id'] == selected and guidance['latest_test_evidence_id'] == test_evidence
            assert guidance['outcomes']['regression'] == ('inconclusive' if runtime_error else 'assertion_failed')
            assert guidance['allowed_interpretations'] == (['inconclusive'] if runtime_error else ['reproduced', 'inconclusive'])
            assert status['action_recovery']['consecutive_errors'] == calls - 4
            interpretation = 'refuted' if calls == 5 else ('inconclusive' if runtime_error else 'reproduced')
            return {'action': 'findings.verdict', 'parameters': {'finding_id': selected, 'test_evidence_id': test_evidence, 'interpretation': interpretation, 'explanation': 'Interpret the actual regression and control outcomes'}}
        if calls == 7:
            assert status['action_recovery']['consecutive_errors'] == 0
            assert status['next_finding_verification']['finding_id'] == first
            return {'action': 'findings.defer', 'parameters': {'finding_id': first, 'reason': 'Separate scenario is not supplied by this owned fixture', 'required_prerequisite': 'A concrete second scenario to test', 'evidence_ids': [source_evidence]}}
        assert calls == 8
        return {'action': 'finish', 'parameters': {'summary': 'Assessed the supplied scenario and retained the uncovered one'}}

    assessment = {'decision': 'agree', 'summary': 'The owned scenario supports the proposed verdict', 'test_assessment': 'Real imported implementation with both controls', 'remaining_concerns': []}
    with endpoint('ollama', replies=lambda _: assessment) as (local, requests), endpoint('openai', replies=reply) as (coding, _):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', local.base_url)
        result = run_agent('Assess the supplied owned scenarios', tmp_path, seed={**source, **tests, 'tests/support.txt': 'Original test support\n'}, coding=coding, use_mcp=False, max_steps=12)
    assert result['status'] == 'incomplete', result
    root = Path(result['report']).parent
    report = json.loads((root / 'report.json').read_text())
    assert report['context_compactions']
    assert sum(event['tool'] == 'findings.test' for event in report['tools']) == 1
    assert len(report['action_errors']) == 2
    errors = [read_evidence(root, identity)['data'] for identity in report['action_errors']]
    assert errors[0]['action']['arguments']['test_evidence_id'] == '0' * 64
    assert errors[1]['verification_recovery']['latest_test_evidence_id'] == test_evidence
    actual = read_evidence(root, test_evidence)['data']['result']
    assert actual['source_hashes'] and actual['support_hashes']
    assert all(case['source_hashes'] for case in actual['cases'].values())
    assert sum(request['path'] == '/api/chat' for request in requests) == (0 if runtime_error else 1)
    assert (root / 'code/access.cjs').read_text() == source['access.cjs']
    assert verify(root)['status'] == 'verified'


@pytest.mark.live
@pytest.mark.parametrize('failure', ['schema', 'unknown_finding', 'premature_finish'])
def test_five_rejected_actions_stop_with_evidence_instead_of_spinning(tmp_path, failure):
    calls = 0

    def reply(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {'action': 'workspace.read', 'parameters': {'path': 'access.cjs'}}
        if calls == 2:
            evidence = latest_observation(body)['evidence_id']
            return {'action': 'findings.record', 'parameters': {'findings': [observation('Unverified access', evidence)]}}
        if failure == 'schema':
            return {'action': 'workspace.list', 'parameters': {'unsupported': True}}
        if failure == 'unknown_finding':
            return {'action': 'findings.verdict', 'parameters': {'finding_id': f'{calls:016x}', 'test_evidence_id': '0' * 64, 'interpretation': 'refuted', 'explanation': 'No matching finding or test evidence'}}
        return {'action': 'finish', 'parameters': {'summary': 'Attempted premature completion'}}

    source, _, _ = fixture('node')
    with endpoint('openai', replies=reply) as (coding, _):
        result = run_agent('Assess the owned access implementation', tmp_path, seed=source, coding=coding, use_mcp=False, max_steps=20)
    assert calls == 7
    assert result['status'] == 'incomplete' and '5 consecutive rejected actions' in result['summary']
    root = Path(result['report']).parent
    report = json.loads((root / 'report.json').read_text())
    assert len(report['action_errors']) == 5
    assert [read_evidence(root, identity)['data']['consecutive_errors'] for identity in report['action_errors']] == [1, 2, 3, 4, 5]
    assert report['findings'][0]['verification']['state'] == 'pending'
    assert [event['tool'] for event in report['tools']] == ['workspace.read', 'findings.record']
    assert verify(root)['status'] == 'verified'


@pytest.mark.live
def test_successful_tool_resets_action_error_streak(tmp_path):
    calls = 0

    def reply(body):
        nonlocal calls
        calls += 1
        if calls in (1, 4):
            return {'action': 'workspace.list', 'parameters': {}}
        if calls in (2, 3, 5, 6):
            return {'action': 'workspace.list', 'parameters': {'unsupported': True}}
        assert controller_status(body)['action_recovery']['consecutive_errors'] == 2
        return {'action': 'finish', 'parameters': {'summary': 'Completed read-only fixture'}}

    with endpoint('openai', replies=reply) as (coding, _):
        result = run_agent('List the owned fixture', tmp_path, seed={'note.txt': 'Owned fixture\n'}, coding=coding, use_mcp=False, max_steps=10)
    assert calls == 7 and result['status'] == 'complete'
    root = Path(result['report']).parent
    report = json.loads((root / 'report.json').read_text())
    assert [read_evidence(root, identity)['data']['consecutive_errors'] for identity in report['action_errors']] == [1, 2, 1, 2]
