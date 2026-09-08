import asyncio
import io
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from textual.widgets import TextArea

from argo import provider_worker, providers
from argo.agent import run_agent
from argo.controller import Cancelled
from argo.evidence import read_evidence, verify
from argo.providers import CodingProfile, ProviderRetryExhausted, ProviderTransientError, generate
from argo.tui import ArgoApp

SCHEMA = {"type": "object", "properties": {"ok": {"const": True}}, "required": ["ok"], "additionalProperties": False}


@contextmanager
def flaky_endpoint(protocol="openai", failure_calls=(), failure="stream", replies=None, error_status=503, event_error=None):
    records = []
    answers = iter(replies or [{"ok": True}] * 20)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, content, content_type="application/json", status=200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self.send(json.dumps({"data": [{"id": "fixture", "context_length": 131072, "max_output_tokens": 32768}]}).encode())

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/api/show":
                self.send(json.dumps({"model_info": {"fixture.context_length": 16384}}).encode())
                return
            records.append(body)
            failing = len(records) in failure_calls
            if failing and failure == "timeout":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.flush()
                time.sleep(0.15)
                try:
                    self.wfile.write(b"{}")
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if failing and failure == "http":
                self.send(b'{"error":{"message":"private provider details"}}', status=error_status)
                return
            if failing and failure == "error_event":
                event = {'error': event_error or {'code': error_status, 'message': 'private provider details'}}
                self.send(((json.dumps(event) + '\n') if protocol == 'ollama' else ('data: ' + json.dumps(event) + '\n\n')).encode(), 'application/x-ndjson' if protocol == 'ollama' else 'text/event-stream')
                return
            value = {"partial": "must never become a tool result"} if failing else next(answers)
            content = json.dumps(value)
            if protocol == "ollama":
                self.send((json.dumps({"message": {"content": content}, "done": not failing}) + "\n").encode(), "application/x-ndjson")
            else:
                events = [{"choices": [{"delta": {"content": content}, "finish_reason": None if failing else "stop"}]}] if protocol == "openai" else [{"type": "content_block_delta", "delta": {"type": "text_delta", "text": content}}]
                if protocol == "anthropic" and not failing:
                    events.append({"type": "message_stop"})
                wire = "".join("data: " + json.dumps(event) + "\n\n" for event in events)
                if protocol == "openai" and not failing:
                    wire += "data: [DONE]\n\n"
                self.send(wire.encode(), "text/event-stream")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield CodingProfile(name="Retry fixture", protocol=protocol, model="fixture", base_url=f"http://127.0.0.1:{server.server_port}"), records
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def immediate_retries(monkeypatch):
    monkeypatch.setattr(providers, "retry_wait", lambda _, check: check())


@pytest.mark.parametrize("protocol", ["openai", "anthropic", "ollama"])
@pytest.mark.parametrize("failure", ["timeout", "stream", "http", "error_event"])
def test_five_automatic_retries_resume_identical_generation(monkeypatch, protocol, failure):
    immediate_retries(monkeypatch)
    if failure == "timeout":
        client = httpx.Client
        monkeypatch.setattr(providers.httpx, "Client", lambda **kwargs: client(**{**kwargs, "timeout": httpx.Timeout(0.05)}))
    progress = []
    with flaky_endpoint(protocol, range(1, 6), failure) as (profile, records):
        assert generate(profile, [{"role": "user", "content": "Original task"}], SCHEMA, on_retry=progress.append) == {"ok": True}
    assert len(records) == 6
    assert all(body == records[0] for body in records)
    waits = [event for event in progress if event["phase"] == "waiting"]
    assert [event["retry"] for event in waits] == [1, 2, 3, 4, 5]
    assert [event["delay_seconds"] for event in waits] == [1, 2, 4, 8, 16]
    assert progress[-1]["phase"] == "recovered" and progress[-1]["retry"] == 5
    assert "private provider details" not in str(progress)


@pytest.mark.parametrize("failure,status", [("stream", 503), ("http", 522), ("error_event", 524)])
def test_sixth_failure_stops_and_reports_exhaustion(monkeypatch, failure, status):
    immediate_retries(monkeypatch)
    events = []
    with flaky_endpoint(failure_calls=range(1, 20), failure=failure, error_status=status) as (profile, records):
        with pytest.raises(ProviderRetryExhausted, match="after 5 automatic retries"):
            generate(profile, [], SCHEMA, on_retry=events.append)
    assert len(records) == 6
    assert events[-1]["phase"] == "exhausted" and events[-1]["retry"] == 5


@pytest.mark.parametrize("status", [522, 524])
@pytest.mark.parametrize("failure", ["http", "error_event"])
def test_gateway_timeouts_retry_identical_generation(monkeypatch, status, failure):
    immediate_retries(monkeypatch)
    events = []
    with flaky_endpoint(failure_calls=[1], failure=failure, error_status=status) as (profile, records):
        assert generate(profile, [{"role": "user", "content": "Original task"}], SCHEMA, on_retry=events.append) == {"ok": True}
    assert len(records) == 2 and records[0] == records[1]
    assert events[0]["reason"] == f"Temporary provider failure (HTTP {status})"
    assert events[-1]["phase"] == "recovered"
    assert "private provider details" not in str(events)


@pytest.mark.parametrize('kind', ['overloaded_error', 'api_error'])
def test_anthropic_typed_stream_failures_recover_without_disclosing_messages(monkeypatch, kind):
    immediate_retries(monkeypatch)
    updates = []
    with flaky_endpoint('anthropic', [1], 'error_event', event_error={'type': kind, 'message': 'private upstream response'}) as (profile, records):
        assert generate(profile, [], SCHEMA, on_retry=updates.append) == {'ok': True}
    assert len(records) == 2
    assert updates[-1]['phase'] == 'recovered'
    assert 'private upstream response' not in str(updates)


@pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 429])
@pytest.mark.parametrize("failure", ["http", "error_event"])
def test_auth_billing_rate_limit_and_bad_requests_do_not_retry(monkeypatch, status, failure):
    immediate_retries(monkeypatch)
    events = []
    with flaky_endpoint(failure_calls=range(1, 10), failure=failure, error_status=status) as (profile, records):
        with pytest.raises(providers.ProviderHTTPError):
            generate(profile, [], SCHEMA, on_retry=events.append)
    assert len(records) == 1 and not events


def test_cancel_during_backoff_does_not_retry_or_wait_for_delay():
    cancellation = threading.Event()

    def check():
        if cancellation.is_set():
            raise Cancelled("Operator stopped recovery")

    with flaky_endpoint(failure_calls=[1]) as (profile, records):
        started = time.monotonic()
        with pytest.raises(Cancelled):
            generate(profile, [], SCHEMA, check=check, on_retry=lambda _: cancellation.set())
        assert time.monotonic() - started < 1
    assert len(records) == 1


def test_task_deadline_and_response_size_are_not_provider_timeout_retries(monkeypatch):
    immediate_retries(monkeypatch)
    events = []
    with flaky_endpoint() as (profile, records):
        providers.model_limits(profile)
        with pytest.raises(TimeoutError, match="Task deadline"):
            generate(profile, [], SCHEMA, check=lambda: (_ for _ in ()).throw(TimeoutError("Task deadline")), on_retry=events.append)
    assert not records and not events
    with pytest.raises(providers.ProviderResponseError, match="transport size"):
        providers.budget(lambda: None, time.monotonic(), 16 * 1024**2 + 1)
    with pytest.raises(ProviderTransientError, match="timed out"):
        providers.budget(lambda: None, time.monotonic() - 301, 1)


@pytest.mark.parametrize("failure", ["timeout", "connection"])
def test_credential_worker_preserves_sanitized_transient_codes(monkeypatch, capsys, failure):
    payload = json.dumps({"profile": CodingProfile().model_dump(), "operation": "generate", "schema": SCHEMA}).encode()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
    monkeypatch.setenv("ARGO_PROVIDER_KEY", "synthetic-worker-fixture")
    error = httpx.ReadTimeout("private upstream text") if failure == "timeout" else httpx.ConnectError("private upstream text")
    monkeypatch.setattr(provider_worker, "exchange", lambda *args, **kwargs: (_ for _ in ()).throw(error))
    provider_worker.main()
    output = capsys.readouterr().out
    assert json.loads(output)["code"] == failure
    assert "private upstream" not in output and "synthetic-worker" not in output


def test_retry_boundary_includes_real_credential_child(monkeypatch, tmp_path):
    immediate_retries(monkeypatch)
    binary = tmp_path / "hush-fixture"
    binary.touch()
    monkeypatch.setattr(providers.shutil, "which", lambda _: str(binary))
    children = []

    def child(arguments, timeout, check, stdin=None):
        check()
        assert "--redact" in arguments
        process = subprocess.run([sys.executable, "-I", "-m", "argo.provider_worker"], input=stdin, capture_output=True, timeout=10, env={**os.environ, "ARGO_PROVIDER_KEY": "synthetic-child-fixture"})
        children.append(json.loads(process.stdout))
        return process.returncode, process.stdout, process.stderr

    monkeypatch.setattr(providers, "command", child)
    with flaky_endpoint(failure_calls=[1, 2]) as (profile, records):
        profile = profile.model_copy(update={"credential": "fixture-reference"})
        assert generate(profile, [], SCHEMA) == {"ok": True}
    assert len(records) == 3
    assert sum(item.get("code") == "incomplete" for item in children) == 2
    assert "synthetic-child-fixture" not in str(children)


@pytest.mark.live
@pytest.mark.parametrize("failure,status", [("stream", 503), ("http", 522), ("error_event", 524)])
def test_retry_after_test_completion_keeps_same_run_without_replaying_tools(tmp_path, monkeypatch, failure, status):
    immediate_retries(monkeypatch)
    replies = [
        {"action": "code.edit", "parameters": {"instruction": "Create addition and regression", "paths": ["add.py", "test_add.py"]}},
        {"files": [{"path": "add.py", "content": "def add(a, b): return a + b\n"}, {"path": "test_add.py", "content": "from add import add\ndef test_add(): assert add(2, 3) == 5\n"}]},
        {"action": "python.tests", "parameters": {}},
        {"action": "finish", "parameters": {"summary": "Completed once after automatic provider recovery"}},
    ]
    progress = []
    with flaky_endpoint(failure_calls=range(4, 9), replies=replies, failure=failure, error_status=status) as (profile, records):
        result = run_agent("Create and test addition", tmp_path, coding=profile, use_mcp=False, max_steps=3, on_progress=progress.append)
    assert result["status"] == "complete", result
    path = Path(result["report"]).parent
    report = json.loads((path / "report.json").read_text())
    assert [tool["tool"] for tool in report["tools"]] == ["code.edit", "python.tests"]
    assert len(records) == 9 and all(request == records[3] for request in records[3:])
    assert len({event["run_id"] for event in progress}) == 1
    retries = [read_evidence(path, identity)["data"] for identity in report["provider_retries"]]
    assert retries[-1]["phase"] == "recovered" and retries[-1]["retry"] == 5
    assert verify(path)["status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (140, 44)])
async def test_tui_shows_five_retries_recovery_and_stop_without_losing_findings(tmp_path, monkeypatch, size):
    monkeypatch.setattr("argo.tui.doctor", lambda: {"ollama": {"local_models": []}})
    app = ArgoApp(tmp_path, project=None, settings_path=tmp_path / "models.json")
    async with app.run_test(size=size) as pilot:
        app.ui("#finding-detail", TextArea).load_text("Existing finding evidence")
        for attempt in range(1, 6):
            details = {"phase": "waiting", "retry": attempt, "max_retries": 5, "delay_seconds": 1, "reason": "Provider request timed out", "operation": "coding"}
            app.progress({"run_id": "a" * 32, "stage": "provider retry", "model": app.coding.model, "provider_retry": details})
            await pilot.pause()
            assert f"retry {attempt}/5" in app.transcript[-1][1]
            assert app.model_activity[app.coding.model]["state"] == "Retrying"
        count = len(app.transcript)
        for phase, expected in [("recovered", "Connection recovered"), ("exhausted", "Stopped after 5 retries")]:
            app.progress({"run_id": "a" * 32, "stage": "provider retry", "model": app.coding.model, "provider_retry": {**details, "phase": phase}})
            await pilot.pause()
            assert expected in app.transcript[-1][1]
        assert len(app.transcript) == count
        assert app.ui("#finding-detail", TextArea).text == "Existing finding evidence"


@pytest.mark.asyncio
async def test_cancellation_remains_responsive_during_automatic_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr("argo.tui.doctor", lambda: {"ollama": {"local_models": []}})
    app = ArgoApp(tmp_path, project=None, settings_path=tmp_path / "models.json")
    async with app.run_test(size=(80, 24)) as pilot:
        app.begin("Owned recovery fixture")
        await pilot.press("escape")
        await asyncio.sleep(0)
        assert app.cancel_event.is_set()
        app.finish()
