import json
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


@contextmanager
def lab_server(fixed=False):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = urlsplit(self.path)
            if route.path == "/":
                body = b"<html><title>Argo isolated fixture</title></html>"
                mime = "text/html"
            elif route.path == "/argo-lab/v1/query":
                name = parse_qs(route.query).get("name", [""])[0]
                with sqlite3.connect(":memory:") as connection:
                    connection.execute("CREATE TABLE accounts (name TEXT)")
                    connection.executemany(
                        "INSERT INTO accounts VALUES (?)", [("guest",), ("alice",), ("bob",)]
                    )
                    if fixed:
                        rows = connection.execute(
                            "SELECT name FROM accounts WHERE name = ?", (name,)
                        ).fetchall()
                    else:
                        rows = connection.execute(
                            f"SELECT name FROM accounts WHERE name = '{name}'"
                        ).fetchall()
                body = json.dumps({"count": len(rows)}).encode()
                mime = "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Argo-Lab", "sqlite-fixture-v1")
            if fixed:
                self.send_header("Content-Security-Policy", "default-src 'none'")
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
        thread.join(timeout=2)


def create_fixture(root, fixed=False):
    root.mkdir(parents=True, exist_ok=True)
    query = (
        'cursor.execute("SELECT name FROM users WHERE name = ?", (name,))'
        if fixed
        else "cursor.execute(f\"SELECT name FROM users WHERE name = '{name}'\")"
    )
    (root / "app.py").write_text(f"def find_user(cursor, name):\n    return {query}\n")
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "argo-fixture",
                "lockfileVersion": 3,
                "packages": {"node_modules/argo-example-package": {"version": "1.0.1" if fixed else "1.0.0"}},
            }
        )
    )
    if not fixed:
        (root / "config.py").write_text('api_key = "ARGO_SYNTHETIC_SECRET_NOT_A_CREDENTIAL_12345"\n')
    return root
