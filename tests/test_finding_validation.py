import copy
import json
from pathlib import Path

import pytest
from test_providers import endpoint
from textual.widgets import DataTable, TextArea

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings, merge_findings, proposed_finding
from argo.agent_models import edit
from argo.contracts import Finding
from argo.evidence import read_evidence, verify
from argo.finding_validation import apply_result, invalidate, queue, run_tests, verdict
from argo.tui import ArgoApp
from argo.workspace import Workspace


def fixture(language="python", vulnerable=True):
    if language == "python":
        source = "def can_read(owner, actor):\n    if not actor:\n        return False\n    return " + ("True" if vulnerable else "owner == actor") + "\n"
        expressions = {"positive_control": "can_read('alice', 'alice')", "negative_control": "not can_read('alice', None)", "regression": "not can_read('alice', 'bob')"}
        paths = {role: f"tests/argo-security/test_{role}.py" for role in expressions}
        tests = {paths[role]: f"from access import can_read\n\ndef test_{role}():\n    assert {expression}\n" for role, expression in expressions.items()}
        return {"access.py": source}, tests, paths
    source = "exports.canRead = (owner, actor) => !!actor && " + ("true" if vulnerable else "owner === actor") + ";\n"
    expressions = {"positive_control": "canRead('alice', 'alice')", "negative_control": "!canRead('alice', null)", "regression": "!canRead('alice', 'bob')"}
    paths = {role: f"tests/argo-security/{role}.test.cjs" for role in expressions}
    tests = {paths[role]: "const test = require('node:test');\nconst assert = require('node:assert/strict');\nconst {canRead} = require('../../access.cjs');\n" + f"test('{role}', () => assert.ok({expression}));\n" for role, expression in expressions.items()}
    return {"access.cjs": source}, tests, paths


def finding(asset):
    return proposed_finding({"path": asset, "title": "Cross-owner access", "explanation": "A different actor can read the owner's data"}, "a" * 64)


@pytest.mark.live
@pytest.mark.parametrize("language", ["python", "node"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_controller_creates_runs_and_interprets_real_controls(tmp_path, monkeypatch, language, vulnerable):
    source, tests, paths = fixture(language, vulnerable)
    asset = next(iter(source))
    expected = "reproduced" if vulnerable else "refuted"
    calls = 0
    identity = None
    evidence = None
    updates = []

    def respond(body):
        nonlocal calls
        if any(message["content"].startswith("Summarize an ongoing") for message in body["messages"]):
            return {"summary": "Finding registered. Its dedicated regression and controls ran. Use the controller queue and latest test evidence to record the verdict. Source unchanged."}
        calls += 1
        messages = body["messages"]
        status = json.loads(messages[-1]["content"].split("Controller status:\n")[1]) if "Controller status:\n" in messages[-1]["content"] else {}
        if calls == 1:
            return {"action": "workspace.read", "parameters": {"path": asset}}
        if calls == 2:
            observed = json.loads(messages[-2]["content"].split("\n", 1)[1])
            return {"action": "findings.record", "parameters": {"findings": [{"path": asset, "title": "Cross-owner access", "severity": "high", "explanation": "Different actors may access owner data", "remediation": "Check ownership", "evidence_ids": [observed["evidence_id"]]}]}}
        if calls == 3:
            assert status["finding_verification"]["counts"] == {"pending": 1}
            return {"action": "finish", "parameters": {"summary": "Premature finish must be rejected"}}
        if calls == 4:
            assert "Verify every finding" in json.dumps(messages)
            return {"action": "code.edit", "parameters": {"paths": list(tests), "instruction": "Create real imported application regression and positive/negative controls. Assert secure behavior."}}
        if calls == 5:
            return {"files": [{"path": path, "content": content} for path, content in tests.items()]}
        if calls == 6:
            return {"action": "findings.test", "parameters": {"finding_id": identity, "hypothesis": "Cross-owner access is accepted", "expected_secure_behavior": "Reject a different authenticated owner", "source_paths": [asset], "tests": paths}}
        if calls == 7:
            assert status["finding_verification"]["counts"] == {"tested": 1}
            return {"action": "findings.verdict", "parameters": {"finding_id": identity, "test_evidence_id": evidence, "interpretation": expected, "explanation": "Real ownership check exercised with legitimate, unauthenticated and cross-owner inputs."}}
        assert status["finding_verification"]["counts"] == {expected: 1}
        return {"action": "finish", "parameters": {"summary": "Controlled runtime scenario assessed"}}

    def progress(event):
        nonlocal identity, evidence
        updates.append(event)
        if event.get("findings"):
            identity = event["findings"][0]["id"]
            evidence = event["findings"][0]["verification"]["test_evidence_id"]

    assessment = {"decision": "agree", "summary": "The runtime evidence supports the proposed scoped verdict", "test_assessment": "Real application behavior with positive/negative controls", "remaining_concerns": []}
    with endpoint("ollama", replies=lambda _: assessment) as (local, _), endpoint("openai", replies=respond) as (coding, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        result = run_agent("Assess the suspected cross-owner bug, create and execute tests; do not fix source", tmp_path / "runs", seed=source, coding=coding, use_mcp=False, on_progress=progress, max_steps=8)
    assert result["status"] == "complete", result
    path = Path(result["report"]).parent
    report = json.loads((path / "report.json").read_text())
    item = report["findings"][0]
    assert item["verification"]["state"] == expected
    assert item["status"] == "suspected"
    assert Finding.model_validate(item)
    assert (path / "code" / asset).read_text() == source[asset]
    test_record = read_evidence(path, item["verification"]["test_evidence_id"])["data"]["result"]
    assert test_record["workspace_unchanged"] is True
    assert test_record["cases"]["positive_control"]["outcome"] == "passed"
    assert test_record["cases"]["negative_control"]["outcome"] == "passed"
    assert test_record["cases"]["regression"]["outcome"] == ("assertion_failed" if vulnerable else "passed")
    assert len(test_record["test_hashes"]) == 3
    assert all(read_evidence(path, case["evidence_id"])["kind"] == "agent_tool" for case in test_record["cases"].values())
    assert "Runtime verification: " + expected in (path / "report.md").read_text()
    assert load_agent_findings(path, {**report, "findings": []})[0]["verification"] == item["verification"]
    assert verify(path)["status"] == "verified"
    assert any(event.get("findings", [{}])[0].get("verification", {}).get("state") == expected for event in updates if event.get("findings"))


@pytest.mark.live
@pytest.mark.parametrize("language", ["python", "node"])
def test_worker_rejects_skip_empty_import_and_runtime_errors(language):
    if language == "python":
        name = "tests/argo-security/test_probe.py"
        contents = ["", "import missing_argo_fixture\n", "import pytest\n@pytest.mark.skip\ndef test_skipped():\n    pass\n", "def test_error():\n    raise RuntimeError('fixture failure')\n", "import pytest\npytest.exit('no tests', 0)\n"]
    else:
        name = "tests/argo-security/probe.test.cjs"
        contents = ["", "require('missing_argo_fixture');\n", "require('node:test')('skip', {skip: true}, () => {});\n", "require('node:test')('error', () => {throw new Error('fixture failure')});\n", "process.exit(0);\n"]
    with Workspace() as workspace:
        for content in contents:
            workspace.call("write", files={name: content})
            output = workspace.call("finding_test", path=name)
            assert output["outcome"] == "inconclusive", (content, output)
        with pytest.raises(ValueError):
            workspace.call("finding_test", path="../outside.py")
        workspace.call("write", files={"test_outside.py": "def test_ok(): assert True"})
        with pytest.raises(ValueError, match="inside tests/argo-security"):
            workspace.call("finding_test", path="test_outside.py")


def recorded_test():
    source, tests, paths = fixture()
    item = finding("access.py")
    result = {
        "finding_id": item["id"], "workspace_unchanged": True,
        "source_paths": ["access.py"], "source_hashes": {"access.py": "a" * 64}, "test_hashes": {paths["regression"]: "b" * 64},
        "cases": {role: {"outcome": "assertion_failed" if role == "regression" else "passed"} for role in paths},
    }
    apply_result(item, "findings.test", result, "c" * 64)
    arguments = {"finding_id": item["id"], "test_evidence_id": "c" * 64, "interpretation": "reproduced", "explanation": "Controlled assertion failed"}
    return item, result, arguments


@pytest.mark.parametrize("problem", ["wrong_evidence", "wrong_finding", "controls", "mutation", "regression_error", "contradiction", "stale"])
def test_verdict_denies_unrelated_stale_or_inconclusive_execution(problem):
    item, result, arguments = recorded_test()
    if problem == "wrong_evidence":
        arguments["test_evidence_id"] = "d" * 64
    elif problem == "wrong_finding":
        result["finding_id"] = "e" * 16
    elif problem == "controls":
        result["cases"]["negative_control"]["outcome"] = "assertion_failed"
    elif problem == "mutation":
        result["workspace_unchanged"] = False
    elif problem == "regression_error":
        result["cases"]["regression"]["outcome"] = "inconclusive"
    elif problem == "contradiction":
        arguments["interpretation"] = "refuted"
    else:
        item["verification"]["state"] = "stale"
    with pytest.raises(ValueError):
        verdict(item, arguments, result)


@pytest.mark.live
def test_unchanged_hashes_retests_and_missing_source_denials():
    source, tests, paths = fixture()
    item = finding("access.py")
    arguments = {"finding_id": item["id"], "source_paths": ["access.py"], "hypothesis": "Cross-owner access", "expected_secure_behavior": "Reject", "tests": paths}
    with Workspace() as workspace:
        workspace.call("write", files={**source, **tests})
        for invalid in [{**arguments, "source_paths": ["absent.py"]}, {**arguments, "tests": dict.fromkeys(paths, paths["regression"])}]:
            with pytest.raises(ValueError):
                run_tests(workspace, item, invalid, lambda *_: "b" * 64)
        result = run_tests(workspace, item, arguments, lambda *_: "b" * 64)
        apply_result(item, "findings.test", result, "c" * 64)
        interpretation = verdict(item, {"finding_id": item["id"], "test_evidence_id": "c" * 64, "interpretation": "reproduced", "explanation": "Observed cross-owner access"}, result)
        apply_result(item, "findings.verdict", interpretation, "d" * 64)
        files = workspace.call("export")["files"]
        assert not invalidate([item], {**files, "tests/argo-security/test_other.py": "def test_other(): pass"}, {})
        helper_change = copy.deepcopy(item)
        assert invalidate([helper_change], {**files, "tests/conftest.py": "import pytest\n"}, {})
        assert merge_findings([item], [finding("access.py")])[0]["verification"]["state"] == "reproduced"
        edited_test = copy.deepcopy(item)
        assert invalidate([edited_test], {**files, paths["regression"]: "def test_weakened(): pass"}, {})
        fixed_source, _, _ = fixture(vulnerable=False)
        workspace.call("write", files=fixed_source)
        assert invalidate([item], {**files, **fixed_source}, {})
        assert item["verification"]["state"] == "stale"
        rerun = run_tests(workspace, item, arguments, lambda *_: "e" * 64)
        assert result["test_hashes"] == rerun["test_hashes"]
        assert rerun["cases"]["regression"]["outcome"] == "passed"
        assert result["source_hashes"] != rerun["source_hashes"]


@pytest.mark.live
def test_test_side_effects_cannot_validate_changed_implementation():
    source, tests, paths = fixture(vulnerable=False)
    tests[paths["positive_control"]] += "\nfrom pathlib import Path\nPath('access.py').write_text('def can_read(owner, actor): return True\\n')\n"
    item = finding("access.py")
    arguments = {"finding_id": item["id"], "source_paths": ["access.py"], "hypothesis": "Cross-owner access", "expected_secure_behavior": "Reject", "tests": paths}
    with Workspace() as workspace:
        workspace.call("write", files={**source, **tests})
        result = run_tests(workspace, item, arguments, lambda *_: "b" * 64)
    assert result["workspace_unchanged"] is False
    assert result["cases"]["negative_control"]["snapshot_matches"] is False
    apply_result(item, "findings.test", result, "c" * 64)
    with pytest.raises(ValueError, match="unchanged"):
        verdict(item, {"finding_id": item["id"], "test_evidence_id": "c" * 64, "interpretation": "reproduced", "explanation": "A test must not change the target"}, result)


@pytest.mark.live
def test_queue_cannot_disappear_on_finish_and_blocker_remains_incomplete(tmp_path):
    calls = 0

    def response(body):
        nonlocal calls
        calls += 1
        messages = body["messages"]
        if calls == 1:
            return {"action": "python.run", "parameters": {"path": "observations.py"}}
        if calls == 2:
            return {"action": "code.edit", "parameters": {"paths": ["app.py"], "instruction": "Change implementation before verifying its findings"}}
        assert "Verify pending findings before editing" in json.dumps(messages)
        status = json.loads(messages[-1]["content"].split("Controller status:\n")[1])
        pending = next(item for item in status["finding_verification"]["items"] if item["state"] == "pending") if calls < 5 else None
        if pending:
            observed = next(json.loads(message["content"].split("\n", 1)[1]) for message in messages if message["content"].startswith("Observed tool result") and '"evidence_id"' in message["content"])
            return {"action": "findings.defer", "parameters": {"finding_id": pending["id"], "reason": "This fixture lacks its remote dependency", "required_prerequisite": "An authorized local service fixture", "evidence_ids": [observed["evidence_id"]]}}
        assert status["finding_verification"]["counts"] == {"inconclusive": 2}
        return {"action": "finish", "parameters": {"summary": "Two explicit validation blockers"}}

    observations = {"findings": [{"path": "app.py", "title": "First hypothesis"}, {"path": "app.py", "title": "Second hypothesis"}]}
    with endpoint("openai", replies=response) as (coding, _):
        result = run_agent("Review fixture hypotheses", tmp_path, seed={"app.py": "value = 1", "observations.py": "import json\nprint(" + repr(json.dumps(observations)) + ")"}, coding=coding, use_mcp=False, max_steps=5)
    assert result["status"] == "incomplete"
    report = json.loads((Path(result["report"]).parent / "report.json").read_text())
    assert report["finding_verification"]["counts"] == {"inconclusive": 2}
    assert any("2/2 findings" in gap for gap in report["coverage_gaps"])
    assert (Path(result["report"]).parent / "code/app.py").read_text() == "value = 1"
    assert queue(report["findings"])["total"] == 2


@pytest.mark.parametrize("recover", [True, False])
def test_coder_rejects_import_only_finding_tests_and_repairs_with_real_assertions(recover):
    path = "tests/argo-security/test_owner.py"
    placeholder = {"files": [{"path": path, "content": "from access import can_read\n"}]}
    actual = {"files": [{"path": path, "content": "from access import can_read\n\ndef test_owner():\n    assert can_read('alice', 'alice')\n"}]}
    replies = [placeholder, actual] if recover else [placeholder] * 3
    with endpoint("openai", replies=replies) as (profile, records):
        if recover:
            assert "def test_owner" in edit("Test ownership", [path], {"access.py": fixture()[0]["access.py"]}, profile=profile)[path]
        else:
            with pytest.raises(ValueError, match="placeholders alone"):
                edit("Test ownership", [path], {"access.py": fixture()[0]["access.py"]}, profile=profile)
    requests = [record for record in records if record["method"] == "POST"]
    assert len(requests) == (2 if recover else 3)
    assert "Dedicated finding tests" in json.dumps(requests[1]["body"]["messages"])


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (140, 44)])
async def test_tui_shows_verdict_and_associated_tests(tmp_path, monkeypatch, size):
    monkeypatch.setattr("argo.tui.doctor", lambda: {"ollama": {"local_models": []}})
    item, result, arguments = recorded_test()
    apply_result(item, "findings.verdict", verdict(item, arguments, result), "d" * 64)
    app = ArgoApp(tmp_path, project=None, settings_path=tmp_path / "models.json")
    async with app.run_test(size=size) as pilot:
        app.report_data = {"kind": "isolated_agent", "findings": [item]}
        app.refresh_findings()
        await pilot.pause()
        assert "reproduced" in str(app.query_one("#findings", DataTable).get_row_at(0))
        assert "Runtime verification: reproduced" in app.query_one("#finding-detail", TextArea).text
        assert "tests/argo-security/test_regression.py" in app.query_one("#finding-detail", TextArea).text
