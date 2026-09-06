import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from argo.contracts import Actions, Engagement, Scope
from argo.evidence import EvidenceStore
from argo.network import HTTPBroker
from argo.scope import authorize
from argo.webchecks import validate_web


@contextmanager
def website(mode):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            git = b"ref: refs/heads/main\n"
            body = git if self.path == "/.git/HEAD" and mode != "fixed" or mode == "catchall" else b"page"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Api-Key", "synthetic-sensitive-header")
            if mode == "vulnerable" and self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("vulnerable", {"argo.web.git-head", "argo.web.cors-reflection"}),
        ("fixed", set()),
        ("catchall", set()),
    ],
)
def test_live_web_checks_and_negative_controls(tmp_path, mode, expected):
    with website(mode) as endpoint:
        config = authorize(
            Engagement(
                id="web-check",
                purpose="Local authorized fixture",
                scope=Scope(web_origins=[endpoint]),
                actions=Actions(local_audit=False, web_validate=True),
            ),
            "test",
            "fixture",
        )
        broker = HTTPBroker(config)
        store = EvidenceStore(tmp_path / "state", config.id, "a" * 64, 10)
        results = validate_web(endpoint, broker, store)
        store.close()
        assert {result.rule for result in results} == expected
        for result in results:
            assert result.status == ("confirmed" if result.rule == "argo.web.git-head" else "suspected")
        for path in store.path.rglob("*"):
            if path.is_file():
                assert b"synthetic-sensitive-header" not in path.read_bytes()
