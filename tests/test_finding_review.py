import copy
import json
from pathlib import Path

import pytest
from review_helpers import unpack_review
from test_finding_validation import finding, fixture
from test_providers import endpoint

from argo.agent import run_agent
from argo.agent_findings import load_agent_findings, merge_findings
from argo.agent_models import QWEN
from argo.controller import Cancelled
from argo.evidence import EvidenceStore, read_evidence, verify
from argo.finding_review import apply_review, check_review_edit, ensure_review, missing_reviews
from argo.finding_validation import apply_result, hashes
from argo.model_activity import review_text

ASSESSMENT = {"decision": "agree", "summary": "The scoped runtime evidence supports the verdict", "test_assessment": "Actual ownership checks and distinct controls", "remaining_concerns": []}


def test_restored_review_activity_shows_assessment_without_prompt_context():
    result = {**ASSESSMENT, "finding_review": {"phase": "fix"}, "review_context": {"explanation": "UNTRUSTED_SOURCE_PROMPT"}}
    text = review_text(result)
    assert "Fix review · agree" in text
    assert ASSESSMENT["test_assessment"] in text
    assert "UNTRUSTED_SOURCE_PROMPT" not in text


class Snapshot:
    def __init__(self):
        source, tests, paths = fixture()
        self.files = {**source, **tests}
        self.manifests = {}
        self.item = finding("access.py")
        self.result = {"finding_id": self.item["id"], "source_hashes": hashes(self.files), "test_hashes": hashes(tests), "source_paths": ["access.py"], "tests": paths, "support_hashes": hashes(tests), "cases": {}, "workspace_unchanged": True}
        apply_result(self.item, "findings.test", self.result, "b" * 64)
        self.args = {"finding_id": self.item["id"], "test_evidence_id": "b" * 64, "interpretation": "reproduced", "explanation": "Review this owned protocol fixture"}

    def call(self, action):
        return {"files": dict(self.files if action == "export" else self.manifests)}


@pytest.fixture
def review_case(tmp_path):
    snapshot = Snapshot()
    store = EvidenceStore(tmp_path / "runs", "review-fixture", "0" * 64, 32)
    records, updates = [], []

    def record(result):
        identity = store.add("agent_tool", {"action": {"tool": "security.review"}, "result": result})
        records.append(identity)
        apply_review([snapshot.item], result, identity)
        return identity

    def run(check=lambda: None):
        return ensure_review(snapshot.item, snapshot.args, snapshot.result, snapshot, store.path, record, check, lambda **event: updates.append(event))

    yield snapshot, store, records, updates, run
    store.close()


def test_bound_review_reuse_and_stale_source_denial(review_case, monkeypatch):
    snapshot, store, records, updates, run = review_case
    with endpoint("ollama", replies=lambda _: ASSESSMENT) as (local, requests):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        identity = run()
        assert run() == identity
        assert len([r for r in requests if r["path"] == "/api/chat"]) == 1
        assert len(records) == 1
        assert any(event.get("reasoning") for event in updates)
        assert "Private scratchpad" not in json.dumps(read_evidence(store.path, identity))
        snapshot.files["access.py"] += "\nchanged = True\n"
        with pytest.raises(ValueError, match="Workspace changed"):
            run()
        assert snapshot.item["verification"]["state"] == "stale"
        assert len(records) == 1


@pytest.mark.parametrize("capacity,accepted", [(32768, False), (262144, True)])
def test_large_manifest_review_uses_advertised_context_without_omission(review_case, monkeypatch, capacity, accepted):
    snapshot, store, records, _, run = review_case
    lockfile = "# Resolved dependency metadata\n" * 6200
    snapshot.manifests["yarn.lock"] = lockfile
    snapshot.result["source_hashes"] = hashes({**snapshot.files, **snapshot.manifests})
    apply_result(snapshot.item, "findings.test", snapshot.result, "b" * 64)
    metadata = {"capabilities": ["completion", "thinking"], "model_info": {
        "general.architecture": "qwen35", "qwen35.context_length": capacity,
    }}
    with endpoint("ollama", replies=lambda _: ASSESSMENT, metadata=metadata) as (local, requests):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        if accepted:
            run()
        else:
            with pytest.raises(ValueError, match="did not approve"):
                run()
    chats = [r["body"] for r in requests if r["path"] == "/api/chat"]
    saved = read_evidence(store.path, records[0])["data"]["result"]
    assert saved["review_context"]["manifests"]["yarn.lock"] == lockfile
    if accepted:
        assert saved["status"] == "complete"
        assert len(chats) == 1
        assert 32768 < chats[0]["options"]["num_ctx"] < capacity
        assert unpack_review(chats[0]["messages"][-1]["content"])["manifests"]["yarn.lock"] == lockfile
    else:
        assert not chats
        assert saved["status"] == "failed"
        assert "advertised context" in saved["error"]


@pytest.mark.parametrize("change", ["test_id", "claim", "source"])
def test_review_binding_never_reuses_a_different_snapshot(review_case, monkeypatch, change):
    snapshot, _, records, _, run = review_case
    with endpoint("ollama", replies=lambda _: ASSESSMENT) as (local, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        first = run()
        if change == "test_id":
            snapshot.args["test_evidence_id"] = "c" * 64
            apply_result(snapshot.item, "findings.test", snapshot.result, "c" * 64)
        elif change == "claim":
            snapshot.item["explanation"] = "Another scoped claim"
        else:
            snapshot.files["access.py"] += "\n# Updated implementation\n"
            snapshot.result["source_hashes"] = hashes(snapshot.files)
            apply_result(snapshot.item, "findings.test", snapshot.result, "b" * 64)
        assert run() != first
        assert len(records) == 2


@pytest.mark.parametrize("failure", ["http", "incomplete", "format", "length", "context", "changed"])
def test_failed_reviews_are_durable_and_cannot_approve(review_case, monkeypatch, failure):
    snapshot, store, records, _, run = review_case

    def reply(_):
        if failure == "changed":
            snapshot.manifests["package.json"] = '{"changed":true}'
        return {"ok": True} if failure == "format" else ASSESSMENT

    chunks = [{"message": {"content": json.dumps(ASSESSMENT)}, "done": failure == "length", "done_reason": "length"}] if failure in {"length", "incomplete"} else None
    if failure == "context":
        snapshot.files["access.py"] *= 10000
        snapshot.result["source_hashes"] = hashes(snapshot.files)
        apply_result(snapshot.item, "findings.test", snapshot.result, "b" * 64)
    with endpoint("ollama", replies=reply, status=401 if failure == "http" else 200, chunks=chunks) as (local, requests):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        with pytest.raises(ValueError, match="did not approve"):
            run()
    result = read_evidence(store.path, records[0])["data"]["result"]
    assert result["status"] == "failed"
    assert result["decision"] == "insufficient_context"
    assert snapshot.item["verification"]["state"] != "reproduced"
    assert len([r for r in requests if r["path"] == "/api/chat"]) == (2 if failure == "length" else 0 if failure in {"http", "context"} else 1)


@pytest.mark.parametrize("when", ["before", "during"])
def test_cancellation_does_not_authorize_a_verdict(review_case, monkeypatch, when):
    snapshot, _, _, _, run = review_case
    stop = when == "before"

    def reply(_):
        nonlocal stop
        stop = True
        return ASSESSMENT

    with endpoint("ollama", replies=reply) as (local, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)

        def cancelled():
            if stop:
                raise Cancelled("Operator cancelled")

        with pytest.raises(Cancelled):
            run(cancelled)
    assert snapshot.item["verification"]["state"] == "tested"


def test_finish_requires_both_bound_reviews_and_rejects_manual_approval():
    snapshot = Snapshot()
    item = snapshot.item
    item["verification"]["state"] = "fixed"
    assert missing_reviews([item]) == [item["id"]]
    apply_review([item], {"model": QWEN, "status": "complete", **ASSESSMENT}, "d" * 64)
    assert not item["verification"]["reviews"]
    assert missing_reviews([item]) == [item["id"]]


def test_changed_claim_invalidates_review_and_deferral_keeps_source_scope():
    item = finding("access.py")
    item["verification"].update(state="refuted", reviews=[{"phase": "finding"}])
    changed = copy.deepcopy(item)
    changed["explanation"] = "A different assertion about this file"
    assert merge_findings([item], [changed])[0]["verification"]["state"] == "stale"
    item["verification"]["reviews"] = []
    item["verification"]["source_paths"] = ["access.py", "helper.py"]
    apply_result(item, "findings.defer", {"reason": "Missing context", "required_prerequisite": "Review helper", "evidence_ids": []}, "b" * 64)
    with pytest.raises(ValueError, match="Deferral"):
        check_review_edit([item], ["helper.py"])


@pytest.mark.live
@pytest.mark.parametrize("phase", ["finding", "fix"])
@pytest.mark.parametrize("decision", ["disagree", "insufficient_context", "failed"])
def test_controller_cannot_skip_or_defer_its_way_past_review(tmp_path, monkeypatch, phase, decision):
    source, tests, paths = fixture()
    fixed, _, _ = fixture(vulnerable=False)
    current, tool_evidence, requests_seen = {}, [], []
    calls = 0

    def progress(event):
        if event.get("findings"):
            current.update(copy.deepcopy(event["findings"][0]))

    def action(name, parameters):
        return {"action": name, "parameters": parameters}

    def verdict(interpretation):
        return action("findings.verdict", {"finding_id": current["id"], "test_evidence_id": current["verification"]["test_evidence_id"], "interpretation": interpretation, "explanation": "Observed regression/control results"})

    def test():
        return action("findings.test", {"finding_id": current["id"], "source_paths": ["access.py"], "tests": paths, "hypothesis": "Cross-owner access", "expected_secure_behavior": "Reject a different owner"})

    def defer():
        return action("findings.defer", {"finding_id": current["id"], "reason": "Qwen review did not approve", "required_prerequisite": "Resolve the recorded reviewer objection", "evidence_ids": [current["verification"]["reviews"][-1]["evidence_id"]]})

    def edit():
        return action("code.edit", {"paths": ["access.py"], "instruction": "Enforce ownership"})

    def finish():
        return action("finish", {"summary": "Review remains incomplete"})
    sequence = [test, lambda: verdict("reproduced")]
    if phase == "finding":
        sequence += [edit, defer, edit, finish]
    else:
        sequence += [edit, lambda: {"files": [{"path": path, "content": value} for path, value in fixed.items()]}, test, lambda: verdict("fixed"), finish, defer, lambda: action("python.tests", {}), finish]

    def coordinator(body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return action("workspace.read", {"path": "access.py"})
        if calls == 2:
            observed = json.loads(body["messages"][-2]["content"].split("\n", 1)[1])
            tool_evidence.append(observed["evidence_id"])
            return action("findings.record", {"findings": [{"path": "access.py", "title": "Cross-owner access", "severity": "high", "explanation": "A different actor can access owner data", "remediation": "Check ownership", "evidence_ids": tool_evidence}]})
        return sequence[calls - 3]()

    def reviewer(body):
        context = json.loads(body["messages"][-1]["content"])
        requests_seen.append(context)
        if phase == "fix" and context["proposed_verdict"] == "reproduced":
            return ASSESSMENT
        return {"malformed": True} if decision == "failed" else {**ASSESSMENT, "decision": decision, "summary": "Additional behavioral evidence needed", "remaining_concerns": ["Exercise the relevant dependency"]}

    with endpoint("ollama", replies=reviewer) as (local, _), endpoint("openai", replies=coordinator, metadata={"context_length": 131072}) as (coding, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        result = run_agent("Assess and repair the owned fixture only after review", tmp_path / "runs", seed={**source, **tests}, coding=coding, use_mcp=False, on_progress=progress, max_steps=16)
    root = Path(result["report"]).parent
    report = json.loads((root / "report.json").read_text())
    assert result["status"] == "incomplete", report["summary"]
    assert report["findings"][0]["verification"]["state"] == "inconclusive"
    reviews = report["findings"][0]["verification"]["reviews"]
    assert reviews[-1]["status"] == ("failed" if decision == "failed" else "complete")
    assert reviews[-1]["decision"] != "agree"
    assert len(requests_seen) == (1 if phase == "finding" else 2)
    assert (root / "code/access.py").read_text() == (source if phase == "finding" else fixed)["access.py"]
    assert load_agent_findings(root, {**report, "findings": []}) == report["findings"]
    assert verify(root)["status"] == "verified"
