import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_providers import endpoint

from argo.agent import run_agent
from argo.evidence import LiveProgress, read_actions, read_live
from argo.tui import ArgoApp
from argo.workspace import validate_map


def event(stage, model="deepseek-v4.1-flash", **details):
    return {"kind": "isolated_agent", "run_id": "abc123", "stage": stage, "model": model, **details}


def published(path, run_id="abc123", clock=None):
    run = path / run_id
    run.mkdir(parents=True, exist_ok=True)
    return LiveProgress(run, run_id, clock=clock or (lambda: 0.0)), run


def test_streaming_updates_refresh_the_snapshot_without_growing_the_action_log(tmp_path):
    """A multi-day run must not write one disk line per generated token."""
    ticks = SimpleNamespace(value=0.0)
    live, run = published(tmp_path, clock=lambda: ticks.value)
    live.record(event("step 1/712"), status="running")
    live.record(event("workspace.map"), status="running")
    for index in range(500):
        ticks.value += 0.5  # real streaming spreads over wall-clock time
        live.record(event("security.review", "argo-qwen:27b", reasoning="token " * (index + 1), provisional=True))
    actions, offset = read_actions(run)
    assert [item["stage"] for item in actions] == ["step 1/712", "workspace.map"]
    assert (run / "actions.jsonl").stat().st_size < 2000
    snapshot = read_live(run)
    assert snapshot["models"]["argo-qwen:27b"]["reasoning"].endswith("token ")
    assert snapshot["actions"] == 2
    assert offset == (run / "actions.jsonl").stat().st_size


def test_snapshot_records_how_far_the_run_reached(tmp_path):
    live, run = published(tmp_path)
    live.record(event("step 1/712"), status="running")
    live.record(event("workspace.focus"), status="running")
    live.record(event("step 7/712"), status="running")
    snapshot = read_live(run)
    assert snapshot["step"] == "7/712"
    assert snapshot["stage"] == "step 7/712"
    assert snapshot["status"] == "running"
    live.close("complete")
    assert read_live(run)["status"] == "complete"


def test_a_completed_finding_review_is_kept_as_an_action(tmp_path):
    live, run = published(tmp_path)
    live.record(event("security.review", "argo-qwen:27b", text="partial", provisional=True))
    live.record(event("security.review", "argo-qwen:27b", text="final answer", provisional=False))
    actions, _ = read_actions(run)
    assert [item.get("text") for item in actions] == ["final answer"]


def test_followers_read_only_new_actions(tmp_path):
    live, run = published(tmp_path)
    live.record(event("step 1/712"), status="running")
    first, offset = read_actions(run)
    live.record(event("workspace.focus"), status="running")
    second, offset = read_actions(run, offset)
    assert [item["stage"] for item in first] == ["step 1/712"]
    assert [item["stage"] for item in second] == ["workspace.focus"]
    assert read_actions(run, offset)[0] == []


def test_oversized_reasoning_is_truncated_before_publication(tmp_path):
    live, run = published(tmp_path)
    live.record(event("security.review", "argo-qwen:27b", reasoning="x" * 40000, provisional=True))
    assert len(read_live(run)["models"]["argo-qwen:27b"]["reasoning"]) == 16000


def test_live_progress_refuses_symlinked_and_missing_publications(tmp_path):
    missing = tmp_path / "absent"
    missing.mkdir()
    assert read_live(missing) is None
    assert read_actions(missing) == ([], 0)
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    run = tmp_path / "linked"
    run.mkdir()
    os.symlink(target, run / "live.json")
    assert read_live(run) is None


def test_a_truncated_trailing_line_is_not_replayed(tmp_path):
    live, run = published(tmp_path)
    live.record(event("step 1/712"), status="running")
    with open(run / "actions.jsonl", "a") as stream:
        stream.write('{"stage": "half-written"')
    actions, _ = read_actions(run)
    assert [item["stage"] for item in actions] == ["step 1/712"]


@pytest.mark.parametrize("value", [59, 30 * 24 * 3600 + 1, 3.5, "72"])
def test_task_deadline_rejects_unusable_values(tmp_path, value):
    with pytest.raises(ValueError, match="task_deadline"):
        run_agent("Audit", tmp_path, task_deadline=value)


def test_validate_map_rejects_malformed_entries():
    validate_map({"files": [{"path": "app.py", "bytes": 10, "sha256": "a" * 64}]})
    for broken in (
        {"files": [{"path": "../escape.py", "bytes": 1, "sha256": "a" * 64}]},
        {"files": [{"path": "app.py", "bytes": -1, "sha256": "a" * 64}]},
        {"files": [{"path": "app.py", "bytes": 1, "sha256": "nope"}]},
        {"files": "not-a-list"},
    ):
        with pytest.raises(ValueError):
            validate_map(broken)


async def attached(app, pilot):
    for _ in range(100):
        await pilot.pause(0.1)
        if app.ollama_status != "checking":
            break
    app.attach(None)
    for _ in range(80):
        await pilot.pause(0.05)
        if app.follow_offset:
            break


@pytest.mark.asyncio
async def test_the_console_follows_a_run_started_by_another_process(tmp_path):
    """A CLI run publishes progress; the console must reconstruct it without the run in-process."""
    live, run = published(tmp_path, "a" * 32)
    live.record(event("step 1/712"), status="running")
    live.record(event("workspace.map"), status="running")
    live.record(event("workspace.focus"), status="running")
    live.record(event("step 4/712"), status="running")
    app = ArgoApp(tmp_path)
    async with app.run_test(size=(140, 44)) as pilot:
        await attached(app, pilot)
        assert app.follow_path == run
        assert app.follow_offset > 0
        live.record(event("findings.record"), status="running")
        for _ in range(80):
            await pilot.pause(0.05)
            if app.follow_offset == (run / "actions.jsonl").stat().st_size:
                break
        assert app.follow_offset == (run / "actions.jsonl").stat().st_size


@pytest.mark.asyncio
async def test_attaching_without_a_running_run_is_refused(tmp_path):
    live, _ = published(tmp_path, "b" * 32)
    live.record(event("step 1/712"), status="running")
    live.close("complete")
    app = ArgoApp(tmp_path)
    async with app.run_test(size=(140, 44)) as pilot:
        for _ in range(100):
            await pilot.pause(0.1)
            if app.ollama_status != "checking":
                break
        with pytest.raises(ValueError, match="No run is currently publishing"):
            app.attach(None)


@pytest.mark.live
@pytest.mark.parametrize(
    "deadline,elapsed,accepted",
    [(None, 14401, False), (259200, 14401, True), (259200, 259201, False)],
)
def test_the_operator_deadline_replaces_the_four_hour_ceiling(tmp_path, monkeypatch, deadline, elapsed, accepted):
    clock = SimpleNamespace(value=10.0)
    monkeypatch.setattr("argo.agent.time", SimpleNamespace(monotonic=lambda: clock.value))

    def progress(data):
        if data["stage"] == "workspace.read":
            clock.value = 10.0 + elapsed

    actions = [
        {"action": "workspace.read", "parameters": {"path": "app.py"}},
        {"action": "finish", "parameters": {"summary": "The owned source was read."}},
    ]
    with endpoint("openai", replies=actions) as (coding, _):
        result = run_agent(
            "Audit source after a long initial inventory", tmp_path, seed={"app.py": "value = 1"},
            coding=coding, use_mcp=False, max_steps=4, on_progress=progress,
            intelligence_mode="connected", task_deadline=deadline,
        )
    assert result["status"] == ("complete" if accepted else "failed")
    if not accepted:
        assert result["summary"] == "Agent task deadline exceeded"
    report = json.loads((Path(result["report"]).parent / "report.json").read_text())
    assert report["task_deadline_seconds"] == (deadline or 14400)


@pytest.mark.live
def test_a_real_run_publishes_its_actions_and_progress(tmp_path):
    actions = [
        {"action": "workspace.read", "parameters": {"path": "app.py"}},
        {"action": "finish", "parameters": {"summary": "The owned source was read."}},
    ]
    with endpoint("openai", replies=actions) as (coding, _):
        result = run_agent(
            "Read the owned source", tmp_path, seed={"app.py": "value = 1"},
            coding=coding, use_mcp=False, max_steps=3,
        )
    run = Path(result["report"]).parent
    recorded, _ = read_actions(run)
    stages = [item["stage"] for item in recorded]
    assert "workspace.read" in stages
    assert any(stage.startswith("step ") for stage in stages)
    snapshot = read_live(run)
    assert snapshot["status"] == result["status"]
    assert snapshot["run_id"] == result["run_id"]


def test_reviewers_receive_the_output_schema_in_the_prompt_text():
    """Ollama's format parameter is invisible to the model's own reasoning; state the schema too."""
    from argo.agent_models import ANALYST, review_batch

    captured = {}

    def fake_response(model, messages, schema, check, *args, **kwargs):
        captured["system"] = messages[0]["content"]
        captured["schema"] = schema
        return {"summary": "none", "suspected_findings": []}

    import argo.agent_models as agent_models

    original = agent_models.review_response
    agent_models.review_response = fake_response
    try:
        review_batch(ANALYST, {"app.py": "value = 1"}, lambda: None, None)
    finally:
        agent_models.review_response = original
    assert "suspected_findings" in captured["system"]
    assert json.dumps(captured["schema"]) in captured["system"]
    assert "do not infer the field names" in captured["system"]


def test_the_mandatory_finding_review_states_its_schema():
    import argo.finding_review as finding_review
    from argo.finding_review import SCHEMA

    assert "decision" in json.dumps(SCHEMA)
    source = Path(finding_review.__file__).read_text()
    assert "do not infer the field names" in source
    assert "json.dumps(SCHEMA)" in source


def test_large_project_guidance_requires_semantic_slices():
    """A slice that omits the configuration its code reads forces insufficient_context."""
    from argo.agent import LARGE_PROJECT_GUIDANCE

    assert "semantic dependency" in LARGE_PROJECT_GUIDANCE
    assert "configuration, settings" in LARGE_PROJECT_GUIDANCE
    assert "insufficient_context" in LARGE_PROJECT_GUIDANCE


def test_every_specialist_reviewer_gets_a_usable_deadline():
    """VulnLLM produced the best-calibrated analysis yet died on the shortest ceiling."""
    from argo.agent_models import ANALYST, QWEN, REVIEWER, review_limits

    for model in (ANALYST, REVIEWER, QWEN):
        assert review_limits(model).deadline >= 1200, model
    assert review_limits(REVIEWER).read_timeout >= 240


def test_repeated_statements_of_one_issue_are_collapsed():
    from argo.agent_models import deduplicate

    observed = [
        {"issue": "algorithm confusion in `python-jose` (CVE-2024-33663)", "path": "app/routes/auth.py"},
        {"issue": "algorithm confusion in python-jose (CVE-2024-33663)", "path": "app/routes/auth.py"},
        {"issue": "CWE-287: Improper Authentication in python-jose (CVE-2024-33663)", "path": "app/routes/auth.py"},
    ]
    assert len(deduplicate(observed)) == 1


def test_deduplication_keeps_distinct_paths_and_distinct_advisories():
    from argo.agent_models import deduplicate

    distinct = [
        {"issue": "algorithm confusion (CVE-2024-33663)", "path": "app/routes/auth.py"},
        {"issue": "algorithm confusion (CVE-2024-33663)", "path": "app/dependencies.py"},
        {"issue": "form parsing DoS (CVE-2026-53539)", "path": "app/routes/auth.py"},
        {"issue": "missing ownership check", "path": "app/routes/auth.py"},
    ]
    assert len(deduplicate(distinct)) == 4


def test_deduplication_preserves_findings_it_cannot_prove_equivalent():
    """Merging differently worded findings without advisories is the coordinator's judgement."""
    from argo.agent_models import deduplicate

    ambiguous = [
        {"issue": "algorithm_confusion", "path": "app/routes/auth.py"},
        {"issue": "insecure algorithm handling", "path": "app/routes/auth.py"},
    ]
    assert len(deduplicate(ambiguous)) == 2


def test_slice_selection_is_visible_in_the_action_log(tmp_path):
    """Following a run must show which files are under review, not just the tool name."""
    live, run = published(tmp_path)
    live.record(event("workspace.focus", paths=["app/auth.py", "app/config.py"], path_count=2), status="running")
    actions, _ = read_actions(run)
    assert actions[0]["paths"] == ["app/auth.py", "app/config.py"]
    assert actions[0]["path_count"] == 2


def test_a_large_selection_is_bounded_in_the_action_log(tmp_path):
    live, run = published(tmp_path)
    selection = [f"app/module_{index:03d}.py" for index in range(400)]
    live.record(event("workspace.focus", paths=selection[:50], path_count=len(selection)), status="running")
    actions, _ = read_actions(run)
    assert len(actions[0]["paths"]) == 50
    assert actions[0]["path_count"] == 400


def test_review_prompt_guards_the_observed_false_positive_classes():
    """Foundation-Sec reported post-mortem comments and non-existent endpoints as live defects."""
    import argo.agent_models as agent_models

    captured = {}

    def fake_response(model, messages, schema, check, *args, **kwargs):
        captured["system"] = messages[0]["content"]
        return {"summary": "none", "suspected_findings": []}

    original = agent_models.review_response
    agent_models.review_response = fake_response
    try:
        agent_models.review_batch(agent_models.ANALYST, {"app.py": "value = 1"}, lambda: None, None)
    finally:
        agent_models.review_response = original
    system = captured["system"]
    assert "history, not a current defect" in system
    assert "this file does not contain" in system
    assert "Judge the code as written" in system


def test_configuration_travels_with_every_batch_of_its_slice():
    """Slicing put config beside its consumers; batching must not strand it again."""
    from argo.agent_models import ANALYST, reference_files, review_batches

    files = {
        "app/auth.py": "from jose import jwt\n" * 400,
        "app/config.py": 'algorithm: str = "HS256"\n' * 5,
        "app/dependencies.py": "def require(): pass\n" * 400,
    }
    reference, omitted = reference_files(files, 16384)
    assert sorted(reference) == ["app/config.py"]
    assert omitted == []
    batches = review_batches(files, ANALYST, None, reference)
    assert len(batches) > 1
    assert any("app/config.py" not in batch for batch in batches)


def test_reference_selection_is_bounded_and_ignores_ordinary_modules():
    from argo.agent_models import reference_files

    assert reference_files({"app/routes.py": "x = 1\n", "app/models.py": "y = 2\n"}, 16384) == ({}, [])
    huge = {"app/config.py": "setting = 1\n" * 200000}
    carried, omitted = reference_files(huge, 16384)
    assert carried == {}
    assert omitted == ["app/config.py"]  # a blind spot must be named, not dropped silently


def test_reference_context_is_declared_outside_the_review_scope():
    import argo.agent_models as agent_models

    captured = {}

    def fake_response(model, messages, schema, check, *args, **kwargs):
        captured["messages"] = messages
        return {"summary": "none", "suspected_findings": []}

    original = agent_models.review_response
    agent_models.review_response = fake_response
    try:
        agent_models.review_batch(
            agent_models.ANALYST, {"app/auth.py": "value = 1"}, lambda: None, None,
            reference={"app/config.py": 'algorithm = "HS256"'},
        )
    finally:
        agent_models.review_response = original
    body = " ".join(message["content"] for message in captured["messages"])
    assert "HS256" in body
    assert "NOT the code under review in this batch" in body
    assert "instead of answering insufficient_context" in body


def test_reference_context_does_not_distort_batch_coverage():
    """Reference copies are context, not reviewed content; coverage must still close."""
    from argo.agent_models import ANALYST, reference_files, review_batches

    files = {
        "app/auth.py": "from jose import jwt\n" * 400,
        "app/config.py": 'algorithm: str = "HS256"\n' * 5,
        "app/dependencies.py": "def require(): pass\n" * 400,
    }
    reference, _ = reference_files(files, 16384)
    batches = review_batches(files, ANALYST, None, reference)
    covered = {path: 0 for path in files}
    for batch in batches:
        for path, source in batch.items():
            covered[path] += len(source)
    assert covered == {path: len(source) for path, source in files.items()}


def test_advisory_applicability_is_kept_out_of_source_findings():
    """The path enum forces a file choice, so a dependency finding lands on an unrelated file."""
    import argo.agent_models as agent_models

    captured = {}

    def fake_response(model, messages, schema, check, *args, **kwargs):
        captured["system"] = messages[0]["content"]
        captured["schema"] = schema
        return {"summary": "none", "suspected_findings": [],
                "cve_assessments": [{"candidate_id": "a" * 16, "assessment": "not_applicable",
                                     "reason": "r", "prerequisites": "p", "test_plan": "t"}]}

    original = agent_models.review_response
    agent_models.review_response = fake_response
    intelligence = {"advisories": [{"id": "a" * 16, "summary": "advisory"}]}
    try:
        agent_models.review_batch(
            agent_models.ANALYST, {"app/config.py": "setting = 1"}, lambda: None, None, intelligence=intelligence,
        )
    finally:
        agent_models.review_response = original
    assert "in cve_assessments only" in captured["system"]
    assert "never an unrelated file chosen because it is the only one available" in captured["system"]
    assert captured["schema"]["properties"]["suspected_findings"]["items"]["properties"]["path"]["enum"] == ["app/config.py"]


def test_a_killed_run_is_not_reported_as_live(tmp_path):
    """Teardown kills the process before close(), so `running` alone cannot be trusted."""
    from argo.evidence import run_is_live

    live, run = published(tmp_path)
    live.record(event("step 3/712"), status="running")
    snapshot = read_live(run)
    assert snapshot["status"] == "running"
    assert snapshot["pid"] == os.getpid()
    assert run_is_live(snapshot) is True
    assert run_is_live({**snapshot, "pid": 999_999}) is False


def test_liveness_falls_back_to_staleness_without_a_pid():
    from argo.contracts import utc_now
    from argo.evidence import run_is_live

    assert run_is_live({"status": "running", "updated_at": utc_now()}) is True
    assert run_is_live({"status": "running", "updated_at": "2020-01-01T00:00:00+00:00"}) is False
    assert run_is_live({"status": "running", "updated_at": "not-a-date"}) is False
    assert run_is_live({"status": "complete", "pid": os.getpid()}) is False
    assert run_is_live(None) is False


def test_configuration_too_large_to_carry_is_reported_as_a_blind_spot():
    """A 14 KB settings module is ordinary; silently skipping it hides what the reviewer cannot see."""
    from argo.agent_models import reference_files

    files = {"app/config.py": "setting = 1\n" * 4000, "app/auth.py": "from jose import jwt\n"}
    carried, omitted = reference_files(files, 2000)
    assert carried == {}
    assert omitted == ["app/config.py"]
    generous, none_omitted = reference_files(files, 200000)
    assert sorted(generous) == ["app/config.py"]
    assert none_omitted == []


def test_a_restatement_with_a_trailing_qualifier_is_one_issue():
    """One reviewer filed the same issue twice, differing only by a parenthetical file name."""
    from argo.agent_models import deduplicate

    observed = [
        {"issue": "Missing authorization checks in user-admin routes", "path": "app/config.py"},
        {"issue": "Missing authorization checks in user admin routes (config.py)", "path": "app/config.py"},
    ]
    assert len(deduplicate(observed)) == 1


def test_a_trailing_qualifier_does_not_merge_across_paths_or_distinct_issues():
    from argo.agent_models import deduplicate

    distinct = [
        {"issue": "Missing authorization checks in user admin routes", "path": "app/config.py"},
        {"issue": "Missing authorization checks in user admin routes", "path": "app/main.py"},
        {"issue": "Missing authorization checks in user permissions handling", "path": "app/config.py"},
        {"issue": "Missing input validation", "path": "app/config.py"},
    ]
    assert len(deduplicate(distinct)) == 4


def test_distinct_advisories_survive_the_prefix_rule():
    from argo.agent_models import deduplicate

    advisories = [
        {"issue": "DoS (CVE-2024-53981)", "path": "app/main.py"},
        {"issue": "DoS (CVE-2024-53981) in form parsing", "path": "app/main.py"},
        {"issue": "DoS (CVE-2026-53539)", "path": "app/main.py"},
    ]
    assert len(deduplicate(advisories)) == 2


def test_a_thinking_reviewer_can_afford_its_reasoning_and_its_answer():
    """Ollama counts thinking tokens in num_predict; an 8k first budget never reached the JSON."""
    from argo.agent_models import ANALYST, QWEN, REVIEWER, review_limits

    budgets = review_limits(QWEN).output_budgets
    assert budgets[0] >= 16384, "observed Qwen reasoning alone exceeded the previous 8192 first budget"
    assert list(budgets) == sorted(budgets)
    for model in (ANALYST, REVIEWER):
        assert review_limits(model).output_budgets[0] <= budgets[0]


def test_the_qwen_context_still_covers_its_largest_output_budget():
    from argo.agent_models import QWEN, review_context_window, review_limits

    metadata = {"model_info": {"general.architecture": "qwen35", "qwen35.context_length": 262144}}
    messages = [{"role": "system", "content": "Review"}, {"role": "user", "content": "value = 1"}]
    schema = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}
    window = review_context_window(QWEN, messages, schema, metadata)
    assert window >= review_limits(QWEN).output_budgets[-1]


def test_raising_the_qwen_ceiling_would_shrink_what_it_can_review():
    """output_budgets[-1] enters the context requirement; a larger ceiling turns reviews into blockers."""
    from argo.agent_models import QWEN, review_limits

    assert review_limits(QWEN).output_budgets[-1] == 16384


def test_the_reference_never_outgrows_the_budget_it_must_fit_in():
    """Sizing the reference against the context window, not the batch budget, starved two reviewers."""
    from argo.agent_models import ANALYST, batch_budget, reference_files, review_batches
    from argo.context_budget import estimate_tokens

    files = {
        "app/config.py": "setting = 1\n" * 1200,
        "app/rbac_constants.py": "MODULI = []\n" * 40,
        "app/auth.py": "from jose import jwt\n" * 200,
    }
    intelligence = {"advisories": [{"id": "a" * 16, "summary": "s" * 400, "details": "d" * 800} for _ in range(3)]}
    budget = batch_budget(ANALYST, intelligence)
    reference, omitted = reference_files(files, budget)
    assert estimate_tokens(reference) < budget, "the reference must leave room for the code under review"
    assert omitted, "configuration that cannot fit must be named"
    assert review_batches(files, ANALYST, intelligence, reference)


def test_a_controller_budget_error_names_its_cause():
    """The real message was replaced by a generic failure, hiding why two reviewers died."""
    from argo.agent_models import local_model_error

    assert local_model_error(ValueError("CVE context is too large; select fewer advisory candidates")) == (
        "CVE context is too large; select fewer advisory candidates"
    )
    assert local_model_error(RuntimeError("boom")) == "The local review failed before producing a valid answer."


def test_redaction_preserves_fstring_placeholders_and_the_closing_quote():
    """Redacting `{token}` turned valid source into an apparent bug and broke the string literal."""
    from argo.evidence import redact

    source = 'setup_link = f"https://app.credilex.it/auth/reset-password?token={token}"'
    assert redact(source) == source
    multi = 'url = f"https://x.it/cb?token={reset_token}&u={uid}"'
    assert redact(multi) == multi


def test_redaction_still_removes_a_real_url_secret():
    from argo.evidence import redact

    assert redact('link = "https://x.it/cb?token=eyJhbGciOiJIUzI1NiJ9.abc.def"') == (
        'link = "https://x.it/cb?token=[redacted]"'
    )
    assert redact("GET https://x.it/cb?api_key=AKIAIOSFODNN7EXAMPLE") == "GET https://x.it/cb?api_key=[redacted]"
    assert "[redacted]" in redact("https://user:hunter2@example.invalid/path")


@pytest.mark.live
def test_a_failed_compaction_ends_the_run_with_its_findings_instead_of_losing_them(tmp_path, monkeypatch):
    """A four-hour audit died with 159 findings when one compaction call returned invalid JSON."""
    from argo.conversation import Conversation
    from argo.providers import ProviderResponseError

    original = Conversation.prepare
    calls = {"n": 0}

    def flaky(self, opening, closing, summarize, check=lambda: None, on_compact=lambda _: None):
        calls["n"] += 1
        if calls["n"] == 3:
            raise ProviderResponseError("invalid_json")
        return original(self, opening, closing, summarize, check, on_compact)

    monkeypatch.setattr(Conversation, "prepare", flaky)
    step = {"n": 0}

    def respond(body):
        step["n"] += 1
        if step["n"] == 1:
            return {"action": "workspace.read", "parameters": {"path": "app.py"}}
        text = json.dumps(body).replace('\\"', '"')
        evidence = next(v for v in text.split('"') if len(v) == 64 and all(c in "0123456789abcdef" for c in v))
        return {"action": "findings.record", "parameters": {"findings": [{
            "path": "app.py", "title": "Cross-owner access", "severity": "high",
            "explanation": "A different actor may read owner data", "remediation": "Check ownership",
            "evidence_ids": [evidence],
        }]}}

    with endpoint("openai", replies=respond) as (coding, _):
        result = run_agent(
            "Audit the owned fixture", tmp_path, seed={"app.py": "value = 1"},
            coding=coding, use_mcp=False, max_steps=6, skip_local_reviews=True,
        )
    assert result["status"] == "incomplete", result
    assert result["findings"] >= 1, "findings collected before the failure must survive"
    report = json.loads((Path(result["report"]).parent / "report.json").read_text())
    assert any("Context management failed" in gap for gap in report["coverage_gaps"])
