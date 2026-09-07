import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from textual.widgets import Button, Input, Select

from argo.agent import run_agent
from argo.evidence import verify
from argo.model_dialog import ModelDialog
from argo.providers import CodingProfile, exchange, generate, list_models, load_settings, save_profile
from argo.tui import ArgoApp
from argo.workspace import Workspace

SCHEMA = {"type": "object", "properties": {"ok": {"const": True}}, "required": ["ok"], "additionalProperties": False}


@contextmanager
def endpoint(protocol, replies=None, status=200, json_response=False, reasoning_tokens=0):
    records = []
    iterator = iter(replies) if replies is not None else None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            records.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"models": [{"name": "custom-model"}]} if protocol == "ollama" else {"data": [{"id": "custom-model"}]}).encode())

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            records.append({"method": "POST", "path": self.path, "body": body, "headers": dict(self.headers)})
            result = next(iterator) if iterator is not None else {"ok": True}
            content = json.dumps(result)
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if json_response else ("application/x-ndjson" if protocol == "ollama" else "text/event-stream"))
            self.end_headers()
            if json_response:
                data = {"content": [{"type": "text", "text": content}], "stop_reason": "end_turn"} if protocol == "anthropic" else {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}
                self.wfile.write(json.dumps(data).encode())
            elif protocol == "ollama":
                self.wfile.write((json.dumps({"message": {"content": content}, "done": True}) + "\n").encode())
            else:
                if protocol == "openai":
                    finish = "length" if body.get("max_tokens", 0) < reasoning_tokens else "stop"
                    events = [{"choices": [{"delta": {"content": content[:5]}, "finish_reason": None}]}, {"choices": [{"delta": {"content": content[5:]}, "finish_reason": finish}]}]
                else:
                    events = [{"type": "message_start", "message": {"content": []}}, {"type": "content_block_start", "content_block": {"type": "text", "text": ""}}, {"type": "content_block_delta", "delta": {"type": "text_delta", "text": content[:5]}}, {"type": "content_block_delta", "delta": {"type": "text_delta", "text": content[5:]}}, {"type": "message_stop"}]
                for event in events:
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                if protocol == "openai":
                    self.wfile.write(b"data: [DONE]\n\n")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield CodingProfile(name="Fixture", protocol=protocol, model="custom-model", base_url=f"http://127.0.0.1:{server.server_port}/proxy/v1" if protocol != "ollama" else f"http://127.0.0.1:{server.server_port}"), records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("protocol", ["openai", "anthropic", "ollama"])
def test_provider_http_stream_and_discovery(protocol):
    with endpoint(protocol) as (profile, records):
        assert list_models(profile) == ["custom-model"]
        assert exchange(profile, "generate", [{"role": "system", "content": "System"}, {"role": "user", "content": "Task"}], SCHEMA, key="synthetic-test-credential") == {"ok": True}
        request = records[-1]
        assert request["body"]["model"] == "custom-model"
        if protocol == "anthropic":
            assert request["path"] == "/proxy/v1/messages"
            assert request["headers"]["x-api-key"] == "synthetic-test-credential"
            assert request["headers"]["anthropic-version"] == "2023-06-01"
            assert "System" in request["body"]["system"]
            assert all(m["role"] != "system" for m in request["body"]["messages"])
        else:
            assert request["headers"]["Authorization"] == "Bearer synthetic-test-credential"
            assert request["path"].endswith("/chat/completions" if protocol == "openai" else "/api/chat")


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_provider_nonstream_compatible_response(protocol):
    with endpoint(protocol, json_response=True) as (profile, _):
        assert generate(profile, [{"role": "user", "content": "JSON"}], SCHEMA) == {"ok": True}


@pytest.mark.asyncio
async def test_tui_connection_probe_allows_reasoning_before_json(tmp_path):
    settings = tmp_path / "models.json"
    with endpoint("openai", reasoning_tokens=1024) as (profile, _):
        with pytest.raises(ValueError, match="truncated"):
            generate(profile, [{"role": "user", "content": "JSON"}], SCHEMA, tokens=256)
        save_profile(profile, settings)
        app = ArgoApp(tmp_path / "runs", project=None, settings_path=settings)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.press("f2")
            await pilot.pause()
            button = app.screen.query_one("#coding-test", Button)
            button.press()
            await pilot.pause()
            for _ in range(50):
                if not button.disabled:
                    break
                await pilot.pause(0.1)
            assert "Connected." in str(app.screen.query_one("#coding-result").render())


def test_profiles_url_modes_persistence_and_errors(tmp_path):
    path = tmp_path / "models.json"
    with endpoint("openai") as (profile, records):
        profile = profile.model_copy(update={"base_url": profile.url(), "output_mode": "json_schema", "token_parameter": "max_completion_tokens"})
        save_profile(profile, path)
        assert load_settings(path).coding == profile
        assert path.stat().st_mode & 0o777 == 0o600
        assert generate(profile, [{"role": "user", "content": "JSON"}], SCHEMA) == {"ok": True}
        assert records[-1]["body"]["response_format"]["type"] == "json_schema"
        assert records[-1]["body"]["max_completion_tokens"] == 4096
    with endpoint("anthropic", status=401) as (profile, _):
        with pytest.raises(RuntimeError, match="HTTP 401"):
            generate(profile, [{"role": "user", "content": "JSON"}], SCHEMA)
    with pytest.raises(ValueError):
        CodingProfile(base_url="https://user:password@example.com/v1")


def test_hush_execution_uses_reference_and_fixed_child(monkeypatch, tmp_path):
    binary = tmp_path / "hush"
    binary.touch()
    calls = []
    monkeypatch.setattr("argo.providers.shutil.which", lambda _: str(binary))

    def invoke(args, timeout, check, stdin):
        calls.append((args, json.loads(stdin)))
        return 0, b'{"result":{"ok":true}}', b""

    monkeypatch.setattr("argo.providers.command", invoke)
    profile = CodingProfile(protocol="anthropic", credential="provider-key", base_url="https://example.com/v1")
    assert generate(profile, [{"role": "user", "content": "JSON"}], SCHEMA) == {"ok": True}
    args, payload = calls[0]
    assert args[1:8] == ["run", "--name", "provider-key", "--env", "ARGO_PROVIDER_KEY", "--redact", "--"]
    assert args[-3:] == ["-I", "-m", "argo.provider_worker"]
    assert payload["profile"]["credential"] == "provider-key"


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_credential_worker_delivers_auth_without_returning_key(protocol):
    with endpoint(protocol) as (profile, records):
        payload = {"profile": profile.model_dump(), "operation": "generate", "messages": [{"role": "user", "content": "JSON"}], "schema": SCHEMA}
        process = subprocess.run([sys.executable, "-I", "-m", "argo.provider_worker"], input=json.dumps(payload), text=True, capture_output=True, timeout=15, env={**os.environ, "ARGO_PROVIDER_KEY": "synthetic-fixture-key"})
        assert process.returncode == 0
        assert json.loads(process.stdout) == {"result": {"ok": True}}
        assert "synthetic-fixture-key" not in process.stdout + process.stderr
        headers = records[-1]["headers"]
        assert headers.get("x-api-key", headers.get("Authorization")) in {"synthetic-fixture-key", "Bearer synthetic-fixture-key"}


@pytest.mark.live
def test_non_python_changes_are_written_and_reported_as_untested(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    replies = [
        {"action": "code.edit", "parameters": {"paths": ["hello.js"], "instruction": "Export a greeting"}},
        {"files": [{"path": "hello.js", "content": "export const greeting = 'hello';\n"}]},
        {"action": "finish", "parameters": {"summary": "Created the JavaScript module; runtime was not tested"}},
    ]
    with endpoint("openai", replies) as (profile, _):
        result = run_agent("Create hello.js", tmp_path / "runs", project=project, coding=profile, use_mcp=False)
    assert result["status"] == "complete"
    assert (project / "hello.js").read_text() == "export const greeting = 'hello';\n"
    report = json.loads(Path(result["report"]).with_suffix(".json").read_text())
    assert any("without runtime verification" in gap for gap in report["coverage_gaps"])


@pytest.mark.live
def test_mount_writes_survive_and_outside_stays_unavailable(tmp_path):
    project = tmp_path / "my project"
    project.mkdir()
    original = project / "app.py"
    original.write_text("VALUE = 1\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    with Workspace(project=project) as worker:
        mounts = worker.inspect()["Mounts"]
        assert len(mounts) == 1 and mounts[0]["RW"]
        assert mounts[0]["Destination"] == "/workspace"
        worker.call("write", files={"app.py": "VALUE = 2\n"}, expected={"app.py": "VALUE = 1\n"})
        assert original.read_text() == "VALUE = 2\n"
        original.write_text("VALUE = 3\n")
        with pytest.raises(ValueError, match="File changed"):
            worker.call("write", files={"app.py": "VALUE = 4\n"}, expected={"app.py": "VALUE = 2\n"})
        worker.call("write", files={"probe.py": f"from pathlib import Path\nassert not Path({str(outside)!r}).exists()\nassert not Path('/var/run/docker.sock').exists()\nPath('/workspace/from_code.txt').write_text('written inside container')\n"})
        assert worker.call("python", path="probe.py")["exit_code"] == 0
    assert original.read_text() == "VALUE = 3\n"
    assert (project / "from_code.txt").read_text() == "written inside container"
    assert outside.read_text() == "outside"


def responses():
    return [
        {"action": "code.edit", "parameters": {"paths": ["app.py", "tests/test_app.py"], "instruction": "Fix addition and test it"}},
        {"files": [{"path": "app.py", "content": "def add(a, b):\n    return a + b\n"}, {"path": "tests/test_app.py", "content": "from app import add\ndef test_add():\n    assert add(2, 3) == 5\n"}]},
        {"action": "python.tests", "parameters": {}},
        {"action": "finish", "parameters": {"summary": "Fixed and tested the mounted project"}},
    ]


@pytest.mark.live
@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_agent_uses_selected_endpoint_and_changes_real_project(tmp_path, monkeypatch, protocol):
    monkeypatch.setattr("argo.agent.ready", lambda: pytest.fail("Remote coding must not require local models"))
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def add(a, b):\n    return a - b\n")
    with endpoint(protocol, responses()) as (profile, records):
        result = run_agent("Fix addition", tmp_path / "runs", project=project, coding=profile, use_mcp=False, max_steps=4)
    assert result["status"] == "complete", result
    assert len(records) == 4
    assert all(row["body"]["model"] == "custom-model" for row in records)
    assert "return a + b" in (project / "app.py").read_text()
    assert (project / "tests/test_app.py").exists()
    assert "-    return a - b" in Path(result["diff"]).read_text()
    assert verify(Path(result["report"]).parent)["status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.parametrize("size,protocol", [((140, 44), "openai"), ((80, 24), "anthropic")])
async def test_tui_model_selection_persists_and_edits_launch_directory(tmp_path, monkeypatch, size, protocol):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    settings = tmp_path / "models.json"
    with endpoint(protocol, responses()) as (profile, records):
        app = ArgoApp(tmp_path / "runs", settings_path=settings)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert app.project == project.resolve()
            await pilot.press("f2")
            await pilot.pause()
            assert isinstance(app.screen, ModelDialog)
            app.screen.query_one("#coding-protocol", Select).value = protocol
            await pilot.pause()
            for name, value in [("name", "Fixture remote"), ("url", profile.base_url), ("model", profile.model)]:
                app.screen.query_one("#coding-" + name, Input).value = value
            app.screen.query_one("#coding-save", Button).press()
            await pilot.pause()
            assert app.coding.protocol == protocol
            assert load_settings(settings).coding.model == "custom-model"
            app.dispatch("/mcp off")
            app.dispatch("Create and test addition in this directory")
            for _ in range(300):
                await pilot.pause(0.1)
                if not app.busy:
                    break
            assert not app.busy
            assert app.report_data["status"] == "complete", app.transcript
            assert app.project == project.resolve()
            assert "return a + b" in (project / "app.py").read_text()
            assert len(records) == 4
    reopened = ArgoApp(tmp_path / "runs", project=project, settings_path=settings)
    assert reopened.coding.protocol == protocol
