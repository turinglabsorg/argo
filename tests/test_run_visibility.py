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
