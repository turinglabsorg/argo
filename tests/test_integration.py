import json
import os
import socket
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from argo.cli import demo
from argo.contracts import Actions, Engagement, Intelligence, Scope
from argo.controller import run
from argo.evidence import EvidenceStore, read_state, redact, verify
from argo.inference import analyze
from argo.intelligence import IntelligenceClient
from argo.lab import create_fixture, lab_server
from argo.network import HTTPBroker
from argo.sandbox import command
from argo.scanners import dependencies, read_sources, scan_source
from argo.scope import ScopeError, authorize, check_authorization, digest, origin, save


@pytest.fixture
def engagement(tmp_path):
    root = create_fixture(tmp_path / "repo")
    return authorize(
        Engagement(
            id="integration",
            purpose="Synthetic fixture integration test",
            scope=Scope(repositories=[str(root)]),
        ),
        "test",
        "isolated fixture",
    )


def test_cli_full_offline_workflow(tmp_path, engagement):
    spec = tmp_path / "engagement.json"
    save(spec, engagement)
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "argo.cli",
            "--state-dir",
            str(tmp_path / "state"),
            "run",
            str(spec),
            "--no-model",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    report_path = Path(json.loads(result.stdout)["report"]).with_suffix(".json")
    data = json.loads(report_path.read_text())
    assert data["status"] == "complete"
    assert any(f["rule"] == "argo.python.sql-construction" for f in data["findings"])
    assert any(f["rule"] == "argo.secret-literal" for f in data["findings"])
    assert data["packages"][0]["version"] == "1.0.0"
    for file in (tmp_path / "state").rglob("*"):
        if file.is_file():
            assert b"ARGO_SYNTHETIC_SECRET_NOT_A_CREDENTIAL_12345" not in file.read_bytes()
    assert read_state(report_path.parent)["status"] == "complete"
    assert verify(report_path.parent)["status"] == "verified"
    evidence_file = next((report_path.parent / "evidence").glob("*.json"))
    evidence_file.write_text("changed")
    assert verify(report_path.parent)["status"] == "failed"


def test_scope_mutation_invalidates_authorization(engagement):
    original = digest(engagement)
    check_authorization(engagement)
    engagement.limits.max_total_target_requests += 1
    assert digest(engagement) != original
    with pytest.raises(ScopeError):
        check_authorization(engagement)


@pytest.mark.parametrize("change", ["draft", "expired", "future", "missing"])
def test_invalid_authorization_never_creates_run(tmp_path, engagement, change):
    if change == "draft":
        engagement.authorization.status = "draft"
    elif change == "expired":
        engagement.authorization.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    elif change == "future":
        engagement.authorization.approved_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    else:
        engagement.authorization.reference = None
    with pytest.raises(ScopeError):
        run(engagement, tmp_path / "state")
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize(
    "value",
    [
        "http://127.1",
        "http://2130706433",
        "http://user:pass@example.invalid",
        "file:///tmp/test",
        "http://*.example.invalid",
        "http://example.invalid/path",
        "http://example.invalid.",
    ],
)
def test_ambiguous_origins_rejected(value):
    with pytest.raises(ScopeError):
        origin(value)


def test_source_symlink_and_install_scripts_not_executed(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("do_not_read = 'external-content'\n")
    (root / "escape.py").symlink_to(outside)
    (root / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    (root / ".env").write_text("DO_NOT_READ=synthetic\n")
    (root / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "touch /tmp/argo-should-not-exist"}})
    )
    records = list(read_sources(root, tmp_path / "state", lambda: None))
    assert not any(text and "external-content" in text for _, text, _ in records)
    assert not any(name == ".env" for name, _, _ in records)
    assert any(name == "escape.py" and gap for name, _, gap in records)


def test_fixed_code_has_no_sql_finding():
    source = 'def lookup(cursor, name):\n    return cursor.execute("SELECT name FROM users WHERE name = ?", (name,))\n'
    results, _, _ = scan_source("fixed.py", source)
    assert not results


def test_dependency_inventory_preserves_exact_versions_and_reports_ranges():
    packages, gaps = dependencies(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/@scope/lib": {"version": "2.3.4"},
                    "node_modules/lib": {"version": "^1.0.0"},
                },
            }
        ),
    )
    assert [(p.name, p.version) for p in packages] == [("@scope/lib", "2.3.4")]
    assert gaps
    assert dependencies("yarn.lock", "")[1]


def test_redactor_covers_multiple_secret_forms():
    assert "synthetic-password" not in redact('password = "synthetic-password"')
    assert "ghp_" not in redact("ghp_" + "a" * 30)
    assert "private-data" not in redact(
        "-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----"
    )


def web_engagement(endpoint, max_requests=10):
    item = Engagement(
        id="web-test",
        purpose="Local HTTP fixture",
        scope=Scope(web_origins=[endpoint], excluded_path_prefixes=["/excluded"]),
        actions=Actions(local_audit=False, web_observe=True),
    )
    item.limits.max_requests_per_second_per_target = 10.0
    item.limits.max_total_target_requests = max_requests
    return authorize(item, "test", "loopback fixture")


def test_http_broker_live_positive_and_request_budget():
    with lab_server() as endpoint:
        broker = HTTPBroker(web_engagement(endpoint, 1))
        result = broker.get(endpoint + "/")
        assert result["status"] == 200
        assert result["peer_ip"] == "127.0.0.1"
        with pytest.raises(ScopeError, match="budget"):
            broker.get(endpoint + "/")


@pytest.mark.parametrize(
    "path",
    ["/excluded", "/excluded-child", "/%65xcluded", "/%2565xcluded", "/../allowed", "//another", "/a\\b"],
)
def test_http_broker_blocks_excluded_and_ambiguous_paths(path):
    with lab_server() as endpoint:
        broker = HTTPBroker(web_engagement(endpoint))
        with pytest.raises(ScopeError):
            broker.get(endpoint + path)
        assert broker.requests == 0


def test_http_redirect_cannot_expand_scope():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:11434/api/tags")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        broker = HTTPBroker(web_engagement(endpoint))
        with pytest.raises(ScopeError, match="outside"):
            broker.get(endpoint)
        assert broker.requests == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_dns_rebinding_rejected_before_connect(monkeypatch):
    config = web_engagement("http://public.example.invalid")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))],
    )
    with pytest.raises(ScopeError, match="Forbidden"):
        HTTPBroker(config).get("http://public.example.invalid/")


def test_command_timeout_and_output_bound():
    with pytest.raises(TimeoutError):
        command([sys.executable, "-c", "import time; time.sleep(10)"], 0.1, lambda: None)
    with pytest.raises(ValueError, match="output limit"):
        command([sys.executable, "-c", "print('x'*9000000)"], 5, lambda: None)


def test_evidence_budget_and_file_permissions(tmp_path):
    store = EvidenceStore(tmp_path / "state", "test", "a" * 64, 1)
    with pytest.raises(ValueError, match="budget"):
        store.add("large", {"body": "x" * 2000000})
    identity = store.add("small", {"password": "synthetic-password"})
    path = store.path / "evidence" / f"{identity}.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert "synthetic-password" not in path.read_text()
    store.close()


def test_offline_intelligence_never_connects(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("Offline mode attempted HTTP")

    monkeypatch.setattr(httpx, "Client", forbidden)
    client = IntelligenceClient(Intelligence(), tmp_path / "missing")
    package = dependencies("requirements.txt", "requests==2.0.0")[0][0]
    assert client.package(package)["status"] == "unavailable"
    assert client.cve("CVE-2021-44228")[0]["status"] == "unavailable"


def test_stale_cache_is_not_current(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text(
        json.dumps(
            {
                "packages": {
                    "PyPI/requests@2.0.0": {
                        "retrieved_at": "2020-01-01T00:00:00+00:00",
                        "data": {"vulns": []},
                    }
                }
            }
        )
    )
    client = IntelligenceClient(Intelligence(), path)
    package = dependencies("requirements.txt", "requests==2.0.0")[0][0]
    assert client.package(package)["status"] == "stale"


def test_cloud_model_alias_never_generates(monkeypatch):
    monkeypatch.setattr("argo.inference.local_models", lambda: [])
    with pytest.raises(ValueError, match="cloud"):
        analyze("evil:cloud", [], 1)


def test_full_demo_confirms_only_vulnerable_control(tmp_path):
    result = demo(tmp_path / "state", [], False)
    assert result["status"] == "complete"
    data = json.loads(Path(result["report"]).with_suffix(".json").read_text())
    assert len([f for f in data["findings"] if f["status"] == "confirmed"]) == 1
    assert any(f["rule"] == "osv.ARGO-LAB-001" for f in data["findings"])


def test_retest_does_not_claim_fixed_when_not_detected(tmp_path, engagement):
    before = run(engagement, tmp_path / "state")
    (Path(engagement.scope.repositories[0]) / "app.py").write_text("# fixed control\n")
    after = run(engagement, tmp_path / "state", retest=Path(before["report"]).parent)
    data = json.loads(Path(after["report"]).with_suffix(".json").read_text())
    assert data["retest"]["not_detected"]
    assert "does not mean fixed" in data["retest"]["note"]
