import copy
import json
import sys
from pathlib import Path

import pytest
from test_finding_validation import fixture, recorded_test
from test_providers import endpoint

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings, merge_findings
from argo.agent_models import QWEN
from argo.cli import main
from argo.evidence import read_evidence, verify
from argo.finding_validation import apply_result


@pytest.mark.live
@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_operator_skip_repairs_with_real_tests_and_never_calls_local_models(tmp_path, monkeypatch, protocol):
    source, tests, paths = fixture()
    fixed, _, _ = fixture(vulnerable=False)
    current = {}
    calls = 0

    def forbidden(*args, **kwargs):
        pytest.fail("An explicitly disabled local reviewer was invoked")

    for name in ("ensure_review", "review", "review_team"):
        monkeypatch.setattr("argo.agent." + name, forbidden)

    def progress(event):
        if event.get("findings"):
            current.update(copy.deepcopy(event["findings"][0]))

    def action(name, parameters):
        return {"action": name, "parameters": parameters}

    def run_tests():
        return action("findings.test", {"finding_id": current["id"], "hypothesis": "Cross-owner access", "expected_secure_behavior": "Reject a different owner", "source_paths": ["access.py"], "tests": paths})

    def verdict(value):
        return action("findings.verdict", {"finding_id": current["id"], "test_evidence_id": current["verification"]["test_evidence_id"], "interpretation": value, "explanation": "Actual unchanged ownership controls and regression"})

    def respond(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return action("workspace.read", {"path": "access.py"})
        if calls == 2:
            messages = body["messages"]
            text = json.dumps(messages)
            evidence = next(value for value in text.replace('\\"', '"').split('"') if len(value) == 64 and all(c in "0123456789abcdef" for c in value))
            return action("findings.record", {"findings": [{"path": "access.py", "title": "Cross-owner access", "severity": "high", "explanation": "Different actors can read owner data", "remediation": "Check ownership", "evidence_ids": [evidence]}]})
        sequence = [
            lambda: action("finish", {"summary": "Pending finding must block finish"}),
            run_tests,
            lambda: verdict("fixed"),
            lambda: verdict("reproduced"),
            lambda: action("code.edit", {"paths": [paths["regression"]], "instruction": "Must reject editing a locked test"}),
            lambda: action("code.edit", {"paths": ["access.py"], "instruction": "Enforce ownership"}),
            lambda: {"files": [{"path": path, "content": content} for path, content in fixed.items()]},
            lambda: verdict("fixed"),
            run_tests,
            lambda: verdict("refuted"),
            lambda: verdict("fixed"),
            lambda: action("python.tests", {}),
            lambda: action("finish", {"summary": "Runtime repair verified; local reviews explicitly skipped"}),
        ]
        return sequence[calls - 3]()

    with endpoint(protocol, replies=respond, metadata={"context_length": 131072}) as (coding, _):
        result = run_agent("Repair the owned fixture with the coding model", tmp_path / "runs", seed={**source, **tests}, coding=coding, use_mcp=False, skip_local_reviews=True, on_progress=progress, max_steps=20)
    root = Path(result["report"]).parent
    report = json.loads((root / "report.json").read_text())
    assert result["status"] == "complete", result
    item = report["findings"][0]
    assert item["verification"]["state"] == "fixed"
    assert item["verification"]["reproduction"]
    assert item["verification"]["reviews"] == []
    assert report["local_reviews"] == "skipped_by_operator"
    assert report["finding_reviews"]["required_phases"] == []
    assert report["models"]["security"] == []
    assert "skipped by operator" in (root / "report.md").read_text()
    assert all((root / "code" / path).read_text() == content for path, content in {**fixed, **tests}.items())
    errors = [read_evidence(root, identity)["data"]["error"] for identity in report["action_errors"]]
    assert len(errors) == 5
    assert any("locked" in error for error in errors)
    assert not any(event["tool"] == "security.review" for event in report["tools"])
    assert load_agent_findings(root, {**report, "findings": []}) == report["findings"]
    assert verify(root)["status"] == "verified"


@pytest.mark.parametrize("options", [{"skip_local_reviews": "true"}, {"skip_local_reviews": True, "required_reviews": [QWEN]}])
def test_skip_requires_unambiguous_operator_configuration(tmp_path, options):
    with pytest.raises(ValueError):
        run_agent("Check the fixture", tmp_path / "runs", **options)
    assert not (tmp_path / "runs").exists()


def test_changed_claim_without_local_approval_invalidates_runtime_verdict():
    item, _, arguments = recorded_test()
    apply_result(item, "findings.verdict", {**arguments, "state": "reproduced"}, "d" * 64)
    changed = copy.deepcopy(item)
    changed["explanation"] = "A different claim without local reviews"
    merged = merge_findings([item], [changed])[0]
    assert merged["verification"]["state"] == "stale"
    assert merged["verification"]["reproduction"] == item["verification"]["reproduction"]


@pytest.mark.parametrize("flag", [[], ["--skip-local-reviews"]])
def test_cli_passes_explicit_review_choice(tmp_path, monkeypatch, flag):
    captured = {}

    def run(task, root, **options):
        captured.update(options)
        return {"status": "complete"}

    monkeypatch.setattr("argo.cli.run_agent", run)
    monkeypatch.setattr(sys, "argv", ["argo", "--state-dir", str(tmp_path / "runs"), "agent", "Check fixture", "--isolated", "--no-mcp", *flag])
    assert main() == 0
    assert captured["skip_local_reviews"] == bool(flag)


@pytest.mark.live
def test_model_cannot_invoke_disabled_reviewer_or_change_operator_policy(tmp_path, monkeypatch):
    actions = [
        {"action": "security.review", "parameters": {"model": "qwen", "paths": ["access.py"]}},
        {"action": "workspace.read", "parameters": {"path": "access.py", "skip_local_reviews": False}},
        {"action": "finish", "parameters": {"summary": "No model review performed"}},
    ]
    with endpoint("openai", replies=actions) as (coding, _):
        result = run_agent("Read only", tmp_path / "runs", seed={"access.py": "value = 1\n"}, coding=coding, use_mcp=False, skip_local_reviews=True, max_steps=3)
    root = Path(result["report"]).parent
    report = json.loads((root / "report.json").read_text())
    assert result["status"] == "complete"
    assert len(report["action_errors"]) == 2
    assert report["tools"] == []
    assert report["local_reviews"] == "skipped_by_operator"
