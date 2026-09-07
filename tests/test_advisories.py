import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_providers import endpoint
from textual.widgets import DataTable

from argo.advisories import AdvisoryService, load_mode, review_context, save_mode
from argo.agent import run_agent
from argo.agent_models import SPECIALISTS, review_team
from argo.evidence import read_evidence, verify
from argo.project_inventory import inventory
from argo.tui import ArgoApp
from argo.workspace import Workspace

IDENTITY = "GHSA-aaaa-bbbb-cccc"
CVE = "CVE-2099-12345"
LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "owned-fixture", "version": "1.0.0"},
    "node_modules/jsonwebtoken": {"version": "8.5.1", "resolved": "https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-8.5.1.tgz"},
}})
SOURCE = "module.exports = (jwt, token) => jwt.verify(token, undefined);\n"


@contextmanager
def intelligence_server(monkeypatch, *, paginated=False, malformed=False, malformed_detail=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.respond(None)

        def do_POST(self):
            self.respond(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

        def respond(self, body):
            requests.append((self.path, body))
            if self.path == "/v1/querybatch":
                rows = []
                for query in body["queries"]:
                    row = {"vulns": [{"id": IDENTITY}]} if query["package"]["name"] == "jsonwebtoken" and query["version"] == "8.5.1" else {}
                    if paginated and not query.get("page_token"):
                        row["next_page_token"] = "second-page"
                    rows.append(row)
                data = {"results": rows} if not malformed else {"results": None, "private": "never show raw errors"}
            elif self.path.startswith("/v1/vulns/"):
                data = {"id": IDENTITY, "aliases": [CVE], "summary": "Owned synthetic advisory", "details": "Requires accepting a missing verification key and unsigned input.", "modified": "2026-09-07T00:00:00Z", "database_specific": {"severity": "HIGH"}, "affected": [{"package": {"ecosystem": "npm", "name": "jsonwebtoken"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]}], "references": [{"url": "https://example.invalid/owned-advisory"}]}
            elif self.path.startswith("/data/v1/epss"):
                data = {"data": [{"cve": CVE, "epss": "0.1", "percentile": "0.5", "date": "2026-09-07"}]}
            elif self.path.endswith("known_exploited_vulnerabilities.json"):
                data = {"vulnerabilities": []}
            elif self.path.startswith("/rest/json/cves/2.0"):
                data = {"vulnerabilities": [{"cve": {"id": CVE, "descriptions": [{"lang": "en", "value": "Owned synthetic NVD record"}]}}], "totalResults": 1}
            else:
                self.send_error(404)
                return
            if malformed_detail and self.path.startswith("/v1/vulns/"):
                data.update(malformed_detail)
            encoded = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("argo.intelligence.ORIGINS", {name: f"http://127.0.0.1:{server.server_port}" for name in ("osv", "nvd", "epss", "cisa_kev")})
    try:
        yield requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def project_fixture():
    return inventory({"files": {"package-lock.json": LOCK}}, {"auth.cjs": SOURCE})


def test_inventory_resolves_yarn_and_python_without_guessing_ranges():
    yarn = '# yarn lockfile v1\n\n"express@^4.0.0", express@~4.21.0:\n  version "4.21.2"\n  resolved "https://registry.yarnpkg.com/express/-/express-4.21.2.tgz"\n\n"@private/example@^1":\n  version "1.0.0"\n  resolved "https://registry.npmjs.org/@private/example/-/example-1.0.0.tgz"\n'
    value = inventory({"files": {
        "package.json": '{"dependencies":{"express":"^4.0.0"}}',
        "yarn.lock": yarn,
        "requirements.txt": "Django==3.2.0\nrequests>=2\n",
        "Dockerfile": "FROM node:22.20.0-bookworm\n",
        "service/pyproject.toml": '[project]\nname = "private-project"\n',
        "service/uv.lock": '[[package]]\nname = "jinja2"\nversion = "3.1.0"\nsource = { registry = "https://pypi.org/simple" }\n',
    }}, {"src/app.js": "const express = require('express');"})
    assert {(p["name"], p["version"]) for p in value["packages"]} == {("express", "4.21.2"), ("@private/example", "1.0.0"), ("Django", "3.2.0"), ("jinja2", "3.1.0")}
    assert next(p for p in value["packages"] if p["name"] == "express")["usage_paths"] == ["src/app.js"]
    assert not next(p for p in value["packages"] if p["name"].startswith("@private"))["public"]
    assert any(t.get("cpe") == "cpe:2.3:a:nodejs:node.js:22.20.0:*:*:*:*:*:*:*" for t in value["technologies"])
    assert any("unpinned" in gap for gap in value["coverage_gaps"])


@pytest.mark.parametrize("detail", [{"aliases": None}, {"database_specific": []}, {"affected": [{"package": None}]}, {"affected": [{"package": {"name": "jsonwebtoken"}, "ranges": None}]}])
def test_malformed_advisory_details_are_a_coverage_gap(tmp_path, monkeypatch, detail):
    with intelligence_server(monkeypatch, malformed_detail=detail):
        result = AdvisoryService(tmp_path / "cache", "connected").scan(project_fixture())
    assert result["status"] == "partial" and result["candidates"] == []
    assert any("details unavailable or malformed" in gap for gap in result["coverage_gaps"])


def test_live_intelligence_http_pagination_cache_and_stale_status(tmp_path, monkeypatch):
    with intelligence_server(monkeypatch, paginated=True) as requests:
        service = AdvisoryService(tmp_path / "cache", "connected")
        catalog = service.scan(project_fixture())
        assert catalog["packages_queried"] == 1 and len(catalog["candidates"]) == 1
        candidate = catalog["candidates"][0]
        assert candidate["cve_ids"] == [CVE] and candidate["fixed_versions"] == ["9.0.0"]
        assert candidate["intelligence"][CVE]["kev"]["in_kev"] is False
        assert len([path for path, _ in requests if path == "/v1/querybatch"]) == 2
        size = len(requests)
        assert service.scan(project_fixture())["candidates"] == catalog["candidates"]
        assert len(requests) == size
        enriched = service.enrich([CVE], include_nvd=True)
        assert enriched[CVE]["nvd"]["data"]["id"] == CVE
    for path in (tmp_path / "cache").glob("*.json"):
        record = json.loads(path.read_text())
        record["retrieved_at"] = "2000-01-01T00:00:00+00:00"
        path.write_text(json.dumps(record))
    offline = AdvisoryService(tmp_path / "cache", "offline").scan(project_fixture())
    assert offline["status"] == "partial"
    assert offline["candidates"][0]["freshness"] == "stale"
    assert next((tmp_path / "cache").glob("*.json")).stat().st_mode & 0o777 == 0o600


def test_malformed_or_offline_intelligence_is_not_a_clean_result(tmp_path, monkeypatch):
    with intelligence_server(monkeypatch, malformed=True):
        result = AdvisoryService(tmp_path / "bad", "connected").scan(project_fixture())
    assert result["status"] == "partial" and result["packages_queried"] == 0
    assert result["candidates"] == [] and "never show raw errors" not in str(result)
    offline = AdvisoryService(tmp_path / "empty", "offline").scan(project_fixture())
    assert offline["status"] == "partial" and offline["coverage_gaps"]


def test_fixed_control_and_private_registry_do_not_become_cve_matches(tmp_path, monkeypatch):
    lock = json.loads(LOCK)
    lock["packages"]["node_modules/jsonwebtoken"]["version"] = "9.0.0"
    lock["packages"]["node_modules/private-example"] = {"version": "1.0.0", "resolved": "https://private.invalid/private-example.tgz"}
    with intelligence_server(monkeypatch) as requests:
        result = AdvisoryService(tmp_path / "cache", "connected").scan(inventory({"files": {"package-lock.json": json.dumps(lock)}}))
    assert result["candidates"] == []
    assert result["packages_queried"] == 1
    assert all("private-example" not in json.dumps(body) for _, body in requests)


@pytest.mark.live
def test_worker_reads_large_locks_and_runs_node_controls_with_isolation(tmp_path):
    (tmp_path / "yarn.lock").write_text("# large lock fixture\n" * 11000)
    (tmp_path / "package.json").symlink_to(tmp_path / "yarn.lock")
    with Workspace(project=tmp_path) as workspace:
        manifests = workspace.call("manifests")
        assert len(manifests["files"]["yarn.lock"]) > 96 * 1024
        assert "yarn.lock" not in workspace.call("export")["files"]
        assert any("package.json" in gap for gap in manifests["coverage_gaps"])
        test = "const test = require('node:test'); const assert = require('node:assert/strict'); const fs = require('node:fs'); test('isolation', () => { assert.equal(fs.existsSync('/var/run/docker.sock'), false); assert.throws(() => fs.writeFileSync('/opt/argo/probe', 'x')); });"
        workspace.call("write", files={"tests/argo-security/isolation.test.cjs": test})
        result = workspace.call("node_tests")
        assert result["exit_code"] == 0 and "# pass 1" in result["stdout"]
        workspace.call("write", files={"tests/argo-security/isolation.test.cjs": test + "\ntest('negative control fails', () => assert.equal(1,2));"})
        assert workspace.call("node_tests")["exit_code"] != 0


def assessment(body):
    identities = body["format"]["properties"]["cve_assessments"]["items"]["properties"]["candidate_id"]["enum"]
    return {"summary": "Known advisory requires runtime validation", "suspected_findings": [], "cve_assessments": [{"candidate_id": identity, "assessment": "potentially_applicable", "reason": "The call has no verification key.", "prerequisites": "Unsigned attacker-controlled token.", "test_plan": "Check rejection of unsigned input and acceptance of a valid signed token."} for identity in identities]}


def test_all_reviewers_receive_verified_advisory_context(tmp_path, monkeypatch):
    with intelligence_server(monkeypatch):
        catalog = AdvisoryService(tmp_path / "cache", "connected").scan(project_fixture())
    context = review_context(catalog, ["auth.cjs"])
    requests = []

    def reply(body):
        requests.append(body)
        return assessment(body)

    with endpoint("ollama", replies=reply) as (profile, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", profile.base_url)
        result = review_team({"auth.cjs": SOURCE}, intelligence=context)
    assert {r["model"] for r in result} == set(SPECIALISTS.values())
    assert all(r["status"] == "complete" and r["cve_assessments"] for r in result)
    assert all(CVE in json.dumps(body["messages"]) for body in requests)
    with pytest.raises(ValueError, match="candidate IDs"):
        review_context(catalog, ["auth.cjs"], ["0" * 16])


@pytest.mark.live
def test_coordinator_cve_lookup_review_runtime_evidence_and_saved_findings(tmp_path, monkeypatch):
    step = 0
    candidate_id = None
    test_evidence = None

    def coding_reply(body):
        nonlocal step, candidate_id, test_evidence
        messages = json.dumps(body["messages"])
        if step == 0:
            assert CVE in messages and "9.0.0" in messages
            result = {"action": "security.review_all", "parameters": {"paths": ["auth.cjs"]}}
        elif step == 1:
            result = {"action": "node.tests", "parameters": {}}
        elif step == 2:
            result = {"action": "security.validation", "parameters": {"candidate_id": candidate_id, "test_evidence_ids": [test_evidence], "interpretation": "not_reproduced", "explanation": "Owned fixture controls passed; this fixture does not load a vulnerable package."}}
        elif step == 3:
            result = {"action": "security.cves", "parameters": {}}
        else:
            result = {"action": "finish", "parameters": {"summary": "CVE candidate reviewed; runtime controls recorded without independent confirmation."}}
        step += 1
        return result

    def progress(event):
        nonlocal candidate_id, test_evidence
        for item in event.get("findings", []):
            if item["rule"] == "agent.cve":
                candidate_id = item["id"]
        run_id = event["run_id"]
        for path in (tmp_path / "runs" / run_id / "evidence").glob("*.json"):
            record = json.loads(path.read_text())
            if record.get("kind") == "agent_tool" and record["data"]["action"]["tool"] == "node.tests":
                test_evidence = path.stem

    with intelligence_server(monkeypatch), endpoint("ollama", replies=assessment) as (local, _), endpoint("openai", replies=coding_reply) as (coding, _):
        monkeypatch.setattr("argo.agent_models.ENDPOINT", local.base_url)
        result = run_agent("Audit this Node project and check CVE applicability", tmp_path / "runs", seed={"package-lock.json": LOCK, "auth.cjs": SOURCE, "tests/argo-security/controls.test.cjs": "const test = require('node:test'); const assert = require('node:assert/strict'); test('owned negative control', () => assert.equal(1,1));"}, coding=coding, use_mcp=False, intelligence_mode="connected", on_progress=progress, max_steps=5)
    path = Path(result["report"]).parent
    report = json.loads((path / "report.json").read_text())
    candidate = next(f for f in report["findings"] if f["rule"] == "agent.cve")
    assert report["status"] == "complete"
    assert candidate["status"] == "suspected" and len(candidate["assessments"]) == 3
    assert "Runtime evidence attached" in candidate["validation"]
    assert {r["model"] for r in candidate["assessments"]} == set(SPECIALISTS.values())
    assert all(read_evidence(path, r["evidence_id"])["kind"] == "agent_tool" for r in candidate["assessments"])
    assert verify(path)["status"] == "verified"


@pytest.mark.asyncio
async def test_cve_mode_is_saved_and_controlled_from_the_tui(tmp_path, monkeypatch):
    settings = tmp_path / "intelligence-settings.json"
    assert load_mode(settings) == "offline"
    save_mode("connected", settings)
    assert load_mode(settings) == "connected"
    monkeypatch.setattr("argo.tui.doctor", lambda: {"ollama": {"status": "ready", "local_models": []}})
    app = ArgoApp(tmp_path / "runs", project=None, settings_path=tmp_path / "models.json")
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.intelligence_path == settings
        assert app.query_one("#findings", DataTable) is not None
        await pilot.press("ctrl+l")
        await pilot.press(*"/cve offline", "enter")
        await pilot.pause()
        assert load_mode(settings) == "offline"
