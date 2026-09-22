import copy
import json
import sys
from pathlib import Path

import pytest
from test_finding_validation import fixture
from test_providers import endpoint

from argo.agent import run_agent
from argo.cli import main
from argo.evidence import read_evidence, verify
from argo.tui import ArgoApp


@pytest.mark.live
@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_audit_only_records_findings_without_production_edits(tmp_path, protocol):
    source, tests, paths = fixture()
    current = {}
    calls = 0
    seen = []

    def action(name, parameters):
        return {"action": name, "parameters": parameters}

    def progress(event):
        if event.get("findings"):
            current.update(copy.deepcopy(event["findings"][0]))

    def respond(body):
        nonlocal calls
        seen.append(body)
        if "allowed_paths" in body["messages"][-1]["content"]:
            return {"files": [{"path": path, "content": content} for path, content in tests.items()]}
        calls += 1
        if calls == 1:
            return action("workspace.read", {"path": "access.py"})
        if calls == 2:
            text = json.dumps(body)
            evidence = next(value for value in text.replace('\\"', '"').split('"') if len(value) == 64 and all(c in "0123456789abcdef" for c in value))
            return action("findings.record", {"findings": [{"path": "access.py", "title": "Cross-owner access", "severity": "high", "explanation": "Different actors may access owner data", "remediation": "Check ownership", "evidence_ids": [evidence]}]})
        sequence = [
            lambda: action("code.edit", {"paths": ["access.py"], "instruction": "Must not repair production source"}),
            lambda: action("code.edit", {"paths": list(tests), "instruction": "Create dedicated regression and controls"}),
            lambda: action("findings.test", {"finding_id": current["id"], "hypothesis": "Cross-owner access", "expected_secure_behavior": "Reject a different owner", "source_paths": ["access.py"], "tests": paths}),
            lambda: action("findings.verdict", {"finding_id": current["id"], "test_evidence_id": current["verification"]["test_evidence_id"], "interpretation": "fixed", "explanation": "Must not claim a fix"}),
            lambda: action("findings.verdict", {"finding_id": current["id"], "test_evidence_id": current["verification"]["test_evidence_id"], "interpretation": "reproduced", "explanation": "Regression assertion failed; controls passed"}),
            lambda: action("finish", {"summary": "Audit complete; the defect remains reproduced"}),
        ]
        return sequence[calls - 3]()

    with endpoint(protocol, replies=respond, metadata={"context_length": 131072}) as (coding, _):
        result = run_agent(
            "Audit the owned fixture; do not repair it",
            tmp_path / "runs",
            seed={**source},
            coding=coding,
            use_mcp=False,
            skip_local_reviews=True,
            audit_only=True,
            on_progress=progress,
            max_steps=12,
        )
    root = Path(result["report"]).parent
    report = json.loads((root / "report.json").read_text())
    assert result["status"] == "complete", result
    assert report["audit"] == "findings_and_report_only"
    assert report["findings"][0]["verification"]["state"] == "reproduced"
    assert (root / "code" / "access.py").read_text() == source["access.py"]
    assert "findings and report only" in (root / "report.md").read_text().lower()
    assert any("production source repair is disabled" in gap for gap in report["coverage_gaps"])
    assert any("operator-selected audit" in json.dumps(body) for body in seen)
    errors = [read_evidence(root, identity)["data"]["error"] for identity in report["action_errors"]]
    assert any("production source" in error for error in errors)
    assert any("verified fixes" in error for error in errors)
    assert verify(root)["status"] == "verified"


def test_audit_only_requires_an_operator_boolean(tmp_path):
    with pytest.raises(ValueError, match="operator-selected boolean"):
        run_agent("Check the fixture", tmp_path / "runs", audit_only="true")
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("flag", [[], ["--audit"]])
def test_cli_passes_explicit_audit_choice(tmp_path, monkeypatch, flag):
    captured = {}

    def run(task, root, **options):
        captured.update(options)
        return {"status": "complete"}

    monkeypatch.setattr("argo.cli.run_agent", run)
    monkeypatch.setattr(sys, "argv", ["argo", "--state-dir", str(tmp_path / "runs"), "agent", "Check fixture", "--isolated", "--no-mcp", *flag])
    assert main() == 0
    assert captured["audit_only"] == bool(flag)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 30), (120, 40)])
async def test_tui_audit_override_is_explicit_and_session_only(tmp_path, monkeypatch, size):
    selected = []

    def capture(app, prompt):
        selected.append(app.audit_only)
        app.finish()

    monkeypatch.setattr(ArgoApp, "agent_work", capture)
    app = ArgoApp(tmp_path / "runs", project=None, settings_path=tmp_path / "models.json")
    assert not app.audit_only
    async with app.run_test(size=size) as pilot:
        app.dispatch("/audit on")
        app.dispatch("/audit invalid")
        assert app.audit_only
        app.dispatch("/agent Check findings only")
        assert selected == [True]
        app.dispatch("/audit off")
        assert not app.audit_only
        await pilot.pause()
    assert not ArgoApp(tmp_path / "runs", project=None, settings_path=tmp_path / "models.json").audit_only
