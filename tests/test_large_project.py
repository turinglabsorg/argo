"""The worker's map/selective-export contract that lets the coordinator slice a large project."""

import copy
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
from test_finding_validation import fixture
from test_providers import endpoint, local_inference

from argo import workspace as workspace_module
from argo.agent import run_agent
from argo.evidence import read_evidence, verify
from argo.finding_validation import invalidate
from argo.workspace import Workspace, requirements_digest, worker_image

WORKER = Path(__file__).resolve().parents[1] / "src" / "argo" / "data" / "agent" / "worker.py"


def worker_module(root):
    """Load the worker outside its image; PyYAML only serves Node TAP parsing, unused here."""
    if "yaml" not in sys.modules:
        stub = types.ModuleType("yaml")
        stub.SafeLoader = type("SafeLoader", (), {})
        stub.YAMLError = type("YAMLError", (Exception,), {})
        stub.load = lambda *args, **kwargs: None
        sys.modules["yaml"] = stub
    spec = importlib.util.spec_from_file_location("argo_worker_under_test", WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.ROOT = str(root)
    return module


def large_tree(root, files=60, lines=800):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "access.py").write_text("def can_read(owner, actor):\n    return True\n")
    filler = "x = 'padding line for the working set budget'\n" * lines
    for index in range(files):
        (root / f"module_{index:02d}.py").write_text(filler)
    return root


def test_the_map_describes_the_whole_tree_without_its_contents(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    catalog = worker.file_map()
    assert catalog["file_count"] == 61
    assert catalog["total_bytes"] > 2 * 1024 * 1024
    assert catalog["truncated"] is False
    assert catalog["working_set_budget"] == {"max_files": worker.MAX_FILES, "max_bytes": worker.MAX_TOTAL}
    entry = next(item for item in catalog["files"] if item["path"] == "app/access.py")
    assert set(entry) == {"path", "bytes", "sha256", "reviewable"}
    assert len(entry["sha256"]) == 64


def test_a_whole_tree_export_still_fails_closed_over_budget(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    with pytest.raises(ValueError, match="export budget exceeded"):
        worker.files()


def test_a_selected_slice_returns_only_that_slice(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    selected = worker.files(["app/access.py", "module_00.py"])
    assert sorted(selected) == ["app/access.py", "module_00.py"]
    assert "can_read" in selected["app/access.py"]


def test_a_slice_skips_what_it_cannot_read_instead_of_failing(tmp_path):
    """code.edit exports its targets before writing them, and a new test file does not exist yet."""
    root = large_tree(tmp_path)
    (root / "tests").mkdir()
    (root / "logo.bin").write_bytes(b"\x00\xff\xfe binary")
    worker = worker_module(root)
    selected = worker.files([
        "app/access.py",
        "tests/argo-security/test_new_regression.py",
        "tests/argo-security/test_new_positive_control.py",
        "missing.py",
        "logo.bin",
    ])
    assert sorted(selected) == ["app/access.py"]
    with pytest.raises(ValueError):
        worker.files(["../outside.py"])


def test_a_slice_over_the_working_set_budget_is_refused(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    with pytest.raises(ValueError, match="content budget"):
        worker.files([f"module_{index:02d}.py" for index in range(60)])


def test_a_slice_with_too_many_files_is_refused(tmp_path):
    root = tmp_path / "many"
    root.mkdir()
    for index in range(20):
        (root / f"f{index}.py").write_text("x = 1\n")
    worker = worker_module(root)
    worker.MAX_FILES = 5
    with pytest.raises(ValueError, match="file budget"):
        worker.files([f"f{index}.py" for index in range(20)])


def test_a_slice_cannot_escape_the_workspace(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    for escape in ("../outside.py", "/etc/passwd", "app/../../outside.py"):
        with pytest.raises(ValueError):
            worker.files([escape])


def test_the_map_skips_excluded_directories(tmp_path):
    root = tmp_path / "project"
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("value = 1\n")
    worker = worker_module(root)
    assert [item["path"] for item in worker.file_map()["files"]] == ["src/app.py"]


@pytest.mark.live
def test_a_mounted_large_project_exposes_map_and_slices_through_the_worker(tmp_path):
    """The contract the coordinator relies on, exercised against the real container."""
    root = large_tree(tmp_path / "project")
    with Workspace(project=root) as workspace:
        with pytest.raises(ValueError, match="export budget exceeded"):
            workspace.call("export")
        catalog = workspace.call("map")
        assert catalog["file_count"] == 61
        assert all("content" not in entry for entry in catalog["files"])
        sliced = workspace.call("export", paths=["app/access.py"])["files"]
        assert list(sliced) == ["app/access.py"]
        assert "can_read" in sliced["app/access.py"]
        with pytest.raises(ValueError, match="budget"):
            workspace.call("export", paths=[f"module_{index:02d}.py" for index in range(60)])
        assert workspace.active


@pytest.mark.live
@pytest.mark.parametrize("vulnerable", [True, False])
def test_a_sliced_project_reaches_a_recorded_verdict(tmp_path, monkeypatch, vulnerable):
    """The whole pipeline in the mode the audits use: mounted project, slices, tracked working set.

    The suite only ever proved this chain on a disposable seed, where code.edit never exports the
    file it is about to create. That is why a large project could not create a test at all.
    """
    root = large_tree(tmp_path / "project")
    source, tests, paths = fixture("python", vulnerable)
    (root / "app" / "access.py").write_text(source["access.py"])
    asset = "app/access.py"
    tests = {path: content.replace("from access import", "from app.access import") for path, content in tests.items()}
    expected = "reproduced" if vulnerable else "refuted"
    calls, identity, evidence = 0, None, None

    def respond(body):
        nonlocal calls
        if any(message["content"].startswith("Summarize an ongoing") for message in body["messages"]):
            return {"summary": "Sliced the project, registered one finding, wrote its three tests."}
        calls += 1
        messages = body["messages"]
        if calls == 1:
            return {"action": "workspace.map", "parameters": {"prefix": "app"}}
        if calls == 2:
            return {"action": "workspace.focus", "parameters": {"paths": [asset]}}
        if calls == 3:
            observed = json.loads(messages[-2]["content"].split("\n", 1)[1])
            return {"action": "findings.record", "parameters": {"findings": [{
                "path": asset, "title": "Cross-owner access", "severity": "high",
                "explanation": "A different actor may read the owner's data",
                "remediation": "Compare owner and actor", "evidence_ids": [observed["evidence_id"]]}]}}
        if calls == 4:
            return {"action": "security.review", "parameters": {"model": "qwen", "paths": ["module_00.py"]}}
        if calls == 5:
            return {"action": "code.edit", "parameters": {"paths": list(tests), "instruction": "Write the regression and its controls against the real module"}}
        if calls == 6:
            return {"files": [{"path": path, "content": content} for path, content in tests.items()]}
        if calls == 7:
            return {"action": "findings.test", "parameters": {
                "finding_id": identity, "hypothesis": "A different owner is accepted",
                "expected_secure_behavior": "Reject a different authenticated owner",
                "source_paths": [asset], "tests": paths}}
        if calls == 8:
            return {"action": "findings.verdict", "parameters": {
                "finding_id": identity, "test_evidence_id": evidence, "interpretation": expected,
                "explanation": "The real module was exercised with legitimate, empty and cross-owner actors."}}
        return {"action": "finish", "parameters": {"summary": "One slice reviewed and verified; the rest of the project was not reached."}}

    def progress(event):
        nonlocal identity, evidence
        if event.get("findings"):
            identity = event["findings"][0]["id"]
            evidence = event["findings"][0]["verification"].get("test_evidence_id")

    assessment = {"decision": "agree", "summary": "The runtime evidence supports the scoped verdict",
                  "test_assessment": "Real module with positive and negative controls", "remaining_concerns": []}
    window = {"context_length": 131072, "max_output_tokens": 32768}
    with endpoint("ollama", replies=lambda _: assessment) as (local, _), endpoint("openai", replies=respond, metadata=window) as (coding, _):
        result = run_agent("Audit this large project slice by slice", tmp_path / "runs", project=root,
                           coding=coding, use_mcp=False, audit_only=True, max_steps=12, on_progress=progress,
                           config=local_inference(local.base_url))
    assert result["status"] == "complete", result
    run = Path(result["report"]).parent
    report = json.loads((run / "report.json").read_text())
    item = report["findings"][0]
    assert item["verification"]["state"] == expected
    for path in tests:
        assert (root / path).read_text() == tests[path]
    assert (root / "app" / "access.py").read_text() == source["access.py"]
    record = read_evidence(run, item["verification"]["test_evidence_id"])["data"]["result"]
    assert record["cases"]["positive_control"]["outcome"] == "passed"
    assert record["cases"]["negative_control"]["outcome"] == "passed"
    assert record["cases"]["regression"]["outcome"] == ("assertion_failed" if vulnerable else "passed")
    errors = [read_evidence(run, identity)["data"]["error"] for identity in report["action_errors"]]
    assert any("module_00.py" in error and "findings.defer" in error for error in errors)
    assert any("exceeds the working-set budget" in gap for gap in report["coverage_gaps"])
    assert verify(run)["status"] == "verified"


@pytest.mark.live
def test_deferring_an_unbindable_claim_drains_the_queue_and_reopens_review(tmp_path, monkeypatch):
    """The gate must be a queue, not a deadlock: a claim nobody can test still has to clear it."""
    root = large_tree(tmp_path / "project")
    asset, second = "app/access.py", "module_00.py"
    calls, identity, evidence = 0, None, None

    def respond(body):
        nonlocal calls
        if any(message["content"].startswith("Summarize an ongoing") for message in body["messages"]):
            return {"summary": "One slice focused, one unbindable claim deferred with its reading."}
        calls += 1
        messages = body["messages"]
        if calls == 1:
            return {"action": "workspace.focus", "parameters": {"paths": [asset]}}
        if calls == 2:
            observed = json.loads(messages[-2]["content"].split("\n", 1)[1])
            return {"action": "findings.record", "parameters": {"findings": [{
                "path": asset, "title": "Claimed missing owner check in an endpoint",
                "severity": "medium", "explanation": "The reviewer describes a route this file does not define",
                "remediation": "Confirm the route exists before repairing",
                "evidence_ids": [observed["evidence_id"]]}]}}
        if calls == 3:
            return {"action": "security.review", "parameters": {"model": "qwen", "paths": [second]}}
        if calls == 4:
            return {"action": "findings.defer", "parameters": {
                "finding_id": identity, "reason": "app/access.py defines no route; the claimed endpoint is absent",
                "required_prerequisite": "A module that actually defines the endpoint the claim describes",
                "evidence_ids": [evidence]}}
        if calls == 5:
            return {"action": "security.review", "parameters": {"model": "qwen", "paths": [second]}}
        return {"action": "finish", "parameters": {"summary": "One claim deferred, the next slice reviewed."}}

    def progress(event):
        nonlocal identity, evidence
        if event.get("findings"):
            identity = event["findings"][0]["id"]
            evidence = event["findings"][0]["evidence_ids"][0]

    review = {"summary": "Reviewed", "suspected_findings": []}
    window = {"context_length": 131072, "max_output_tokens": 32768}
    with endpoint("ollama", replies=lambda _: review) as (local, _), endpoint("openai", replies=respond, metadata=window) as (coding, _):
        monkeypatch.setattr("argo.inference.ENDPOINT", local.base_url)
        result = run_agent("Audit this large project slice by slice", tmp_path / "runs", project=root,
                           coding=coding, use_mcp=False, audit_only=True, max_steps=8, on_progress=progress,
                           config=local_inference(local.base_url))
    # A deferred claim is honest incompleteness, not a clean result.
    assert result["status"] == "incomplete", result
    assert result["summary"] == "One claim deferred, the next slice reviewed."
    run = Path(result["report"]).parent
    report = json.loads((run / "report.json").read_text())
    item = report["findings"][0]
    assert item["verification"]["state"] == "inconclusive"
    assert "defines no route" in item["verification"]["explanation"]
    assert [row["tool"] for row in report["tools"]].count("security.review") == 1
    errors = [read_evidence(run, identity)["data"]["error"] for identity in report["action_errors"]]
    assert len(errors) == 1 and second in errors[0]
    assert any("Runtime verification unresolved" in gap for gap in report["coverage_gaps"])
    assert verify(run)["status"] == "verified"


@pytest.mark.live
def test_a_verified_slice_opens_the_next_one(tmp_path, monkeypatch):
    """The loop the audit repeats for every slice, and that no run has ever completed once."""
    root = large_tree(tmp_path / "project")
    source, tests, paths = fixture("python", True)
    (root / "app" / "access.py").write_text(source["access.py"])
    (root / "app" / "billing.py").write_text("def charge(actor, amount):\n    return amount\n")
    first, second = "app/access.py", "app/billing.py"
    tests = {path: content.replace("from access import", "from app.access import") for path, content in tests.items()}
    calls, findings, evidence = 0, {}, {}

    def respond(body):
        nonlocal calls
        if any(message["content"].startswith("Summarize an ongoing") for message in body["messages"]):
            return {"summary": "First slice verified. Second slice focused and reviewed."}
        calls += 1
        messages = body["messages"]
        observed = json.loads(messages[-2]["content"].split("\n", 1)[1]) if "Observed tool result" in messages[-2]["content"] else {}
        if calls == 1:
            return {"action": "workspace.focus", "parameters": {"paths": [first]}}
        if calls == 2:
            return {"action": "findings.record", "parameters": {"findings": [{
                "path": first, "title": "Cross-owner access", "severity": "high",
                "explanation": "A different actor may read the owner's data",
                "remediation": "Compare owner and actor", "evidence_ids": [observed["evidence_id"]]}]}}
        if calls == 3:
            return {"action": "code.edit", "parameters": {"paths": list(tests), "instruction": "Write the regression and its controls"}}
        if calls == 4:
            return {"files": [{"path": path, "content": content} for path, content in tests.items()]}
        if calls == 5:
            return {"action": "findings.test", "parameters": {
                "finding_id": findings[first], "hypothesis": "A different owner is accepted",
                "expected_secure_behavior": "Reject a different authenticated owner",
                "source_paths": [first], "tests": paths}}
        if calls == 6:
            return {"action": "findings.verdict", "parameters": {
                "finding_id": findings[first], "test_evidence_id": evidence[first], "interpretation": "reproduced",
                "explanation": "The real module accepted a different owner under its own controls."}}
        if calls == 7:
            return {"action": "workspace.focus", "parameters": {"paths": [second]}}
        if calls == 8:
            return {"action": "security.review", "parameters": {"model": "qwen", "paths": [second]}}
        return {"action": "finish", "parameters": {"summary": "Slice one verified; slice two reviewed, nothing suspected."}}

    def progress(event):
        for item in event.get("findings") or []:
            findings[item["asset"]] = item["id"]
            if (item.get("verification") or {}).get("test_evidence_id"):
                evidence[item["asset"]] = item["verification"]["test_evidence_id"]

    def reviewer(body):
        """The bound finding review and a plain source review do not share a schema."""
        if "suspected_findings" in (body.get("format") or {}).get("properties", {}):
            return {"summary": "Reviewed", "suspected_findings": []}
        return {"decision": "agree", "summary": "The runtime evidence supports the scoped verdict",
                "test_assessment": "Real module with positive and negative controls", "remaining_concerns": []}

    window = {"context_length": 131072, "max_output_tokens": 32768}
    with endpoint("ollama", replies=reviewer) as (local, _), endpoint("openai", replies=respond, metadata=window) as (coding, _):
        monkeypatch.setattr("argo.inference.ENDPOINT", local.base_url)
        result = run_agent("Audit this large project slice by slice", tmp_path / "runs", project=root,
                           coding=coding, use_mcp=False, audit_only=True, max_steps=12, on_progress=progress,
                           config=local_inference(local.base_url))
    assert result["status"] == "complete", result
    run = Path(result["report"]).parent
    report = json.loads((run / "report.json").read_text())
    assert [item["verification"]["state"] for item in report["findings"]] == ["reproduced"]
    assert [row["tool"] for row in report["tools"]].count("security.review") == 2
    assert report["action_errors"] == []
    for path, content in tests.items():
        assert (root / path).read_text() == content
    assert (root / "app" / "billing.py").read_text() == "def charge(actor, amount):\n    return amount\n"
    # Focusing the next slice must not invalidate what the previous one verified, but a late
    # conftest still can: it changes how the bound tests run.
    item = report["findings"][0]
    exported = {path: (root / path).read_text() for path in item["verification"]["source_hashes"]}
    assert not invalidate([copy.deepcopy(item)], {**exported, "app/extra.py": "value = 1\n"}, {})
    assert invalidate([copy.deepcopy(item)], {**exported, "tests/conftest.py": "import pytest\n"}, {})
    assert verify(run)["status"] == "verified"


@pytest.mark.live
def test_the_recorded_project_worker_runs_the_dedicated_tests(tmp_path, monkeypatch):
    """An audited project's own image must carry the run, and the report must say so.

    Whether a given image imports a given application is the operator's build-time check; what
    the run owes is that the image it was told to use is the one the tests execute in.
    """
    root = large_tree(tmp_path / "project")
    source, tests, paths = fixture("python", True)
    (root / "app" / "access.py").write_text(source["access.py"])
    (root / "requirements.txt").write_text("# only packages the stock worker already carries\npytest==8.3.3\n")
    tests = {path: content.replace("from access import", "from app.access import") for path, content in tests.items()}
    registry = tmp_path / "workers.json"
    monkeypatch.setattr(workspace_module, "PROJECT_WORKERS", registry)
    registry.write_text(json.dumps({"projects": {str(root.resolve()): {
        "image": worker_image(), "base": worker_image(), "requirements": "requirements.txt",
        "requirements_sha256": requirements_digest(root / "requirements.txt")}}}))
    asset, calls, findings, evidence = "app/access.py", 0, {}, {}

    def respond(body):
        nonlocal calls
        if any(message["content"].startswith("Summarize an ongoing") for message in body["messages"]):
            return {"summary": "Focused one slice and verified its finding."}
        calls += 1
        messages = body["messages"]
        if calls == 1:
            return {"action": "workspace.focus", "parameters": {"paths": [asset]}}
        if calls == 2:
            observed = json.loads(messages[-2]["content"].split("\n", 1)[1])
            return {"action": "findings.record", "parameters": {"findings": [{
                "path": asset, "title": "Cross-owner access", "severity": "high",
                "explanation": "A different actor may read the owner's data",
                "remediation": "Compare owner and actor", "evidence_ids": [observed["evidence_id"]]}]}}
        if calls == 3:
            return {"action": "code.edit", "parameters": {"paths": list(tests), "instruction": "Write the regression and its controls"}}
        if calls == 4:
            return {"files": [{"path": path, "content": content} for path, content in tests.items()]}
        if calls == 5:
            return {"action": "findings.test", "parameters": {
                "finding_id": findings[asset], "hypothesis": "A different owner is accepted",
                "expected_secure_behavior": "Reject a different authenticated owner",
                "source_paths": [asset], "tests": paths}}
        if calls == 6:
            return {"action": "findings.verdict", "parameters": {
                "finding_id": findings[asset], "test_evidence_id": evidence[asset], "interpretation": "reproduced",
                "explanation": "The real module accepted a different owner under its own controls."}}
        return {"action": "finish", "parameters": {"summary": "One slice verified inside the project worker."}}

    def progress(event):
        for item in event.get("findings") or []:
            findings[item["asset"]] = item["id"]
            if (item.get("verification") or {}).get("test_evidence_id"):
                evidence[item["asset"]] = item["verification"]["test_evidence_id"]

    assessment = {"decision": "agree", "summary": "The runtime evidence supports the scoped verdict",
                  "test_assessment": "Real module with positive and negative controls", "remaining_concerns": []}
    window = {"context_length": 131072, "max_output_tokens": 32768}
    with endpoint("ollama", replies=lambda _: assessment) as (local, _), endpoint("openai", replies=respond, metadata=window) as (coding, _):
        result = run_agent("Audit this large project slice by slice", tmp_path / "runs", project=root,
                           coding=coding, use_mcp=False, audit_only=True, max_steps=10, on_progress=progress,
                           config=local_inference(local.base_url))
    assert result["status"] == "complete", result
    run = Path(result["report"]).parent
    report = json.loads((run / "report.json").read_text())
    assert report["worker"]["image"] == worker_image()
    assert report["worker"]["project_dependencies"]["requirements"] == "requirements.txt"
    assert any("requirements.txt" in gap and "installed from the public index" in gap for gap in report["coverage_gaps"])
    item = report["findings"][0]
    assert item["verification"]["state"] == "reproduced"
    record = read_evidence(run, item["verification"]["test_evidence_id"])["data"]["result"]
    assert {role: case["outcome"] for role, case in record["cases"].items()} == {
        "positive_control": "passed", "negative_control": "passed", "regression": "assertion_failed"}
    isolation = next(read_evidence(run, entry["id"])["data"] for entry in json.loads((run / "manifest.json").read_text())["evidence"]
                     if read_evidence(run, entry["id"])["kind"] == "workspace_isolation")
    assert isolation["project_worker"]["requirements_sha256"] == requirements_digest(root / "requirements.txt")


@pytest.mark.live
@pytest.mark.parametrize("role,body,expected", [
    ("regression", "def test_owned():\n    assert False\n", "assertion_failed"),
    ("positive_control", "def test_owned():\n    assert True\n", "passed"),
])
def test_a_dedicated_test_ignores_the_audited_project_conftest(tmp_path, role, body, expected):
    """The audited suite must not decide, at collection time, whether a finding can be verified.

    A FastAPI project whose tests/conftest.py imports its application runs that import before any
    dedicated test can prepare its environment, so every case came back inconclusive whatever the
    test itself did. It is also untrusted code executing inside Argo's own verification.
    """
    project = tmp_path / "project"
    (project / "tests" / "argo-security").mkdir(parents=True)
    (project / "tests" / "conftest.py").write_text(
        "raise RuntimeError('the audited suite imports its application at collection time')\n"
    )
    (project / "conftest.py").write_text("raise RuntimeError('and so does the repository root')\n")
    (project / "tests" / "argo-security" / "conftest.py").write_text("import os\n\nos.environ.setdefault('ARGO_OWNED', '1')\n")
    path = f"tests/argo-security/test_owned_{role}.py"
    (project / path).write_text("import os\n\n\n" + body.replace("def test_owned():", "def test_owned():\n    assert os.environ['ARGO_OWNED'] == '1'"))
    with Workspace(project=project) as workspace:
        result = workspace.call("finding_test", path=path)
    assert result["outcome"] == expected, result
    assert result["counts"]["errors"] == 0 and result["counts"]["tests"] == 1
