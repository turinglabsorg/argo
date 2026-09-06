"""Fixed remote MCP adapter, executed in its own container without workspace files."""

import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

LIMIT = 256 * 1024


def endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.port not in {None, 443}:
        raise ValueError("MCP requires a public HTTPS endpoint on port 443 without credentials")
    addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Private and non-public MCP addresses are denied")
    return parsed, sorted(addresses)[0]


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, 443, timeout=12, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class MCP:
    def __init__(self, url):
        self.url = url
        self.session = None
        self.protocol = "2025-06-18"
        self.counter = 0
        self.deadline = time.monotonic() + 50

    def request(self, method, params=None, notification=False):
        if time.monotonic() > self.deadline:
            raise TimeoutError("MCP deadline exceeded")
        parsed, address = endpoint(self.url)
        self.counter += 1
        message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notification:
            message["id"] = self.counter
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": self.protocol}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        connection = PinnedHTTPS(parsed.hostname, address)
        try:
            connection.request("POST", parsed.path or "/", json.dumps(message).encode(), headers)
            response = connection.getresponse()
            if response.status not in {200, 202, 204}:
                raise ValueError("MCP HTTP status " + str(response.status))
            if method == "initialize":
                self.session = response.getheader("Mcp-Session-Id")
                if self.session and (len(self.session) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in self.session)):
                    raise ValueError("Invalid MCP session")
            if notification:
                return {}
            if response.getheader("Content-Type", "").startswith("text/event-stream"):
                total, event = 0, []
                while time.monotonic() < self.deadline:
                    line = response.readline(LIMIT + 1)
                    total += len(line)
                    if total > LIMIT:
                        raise ValueError("MCP response budget exceeded")
                    if not line:
                        break
                    text = line.decode("utf-8").rstrip("\r\n")
                    if text.startswith("data:"):
                        event.append(text[5:].lstrip(" "))
                    elif not text and event:
                        data = json.loads("\n".join(event))
                        event = []
                        if data.get("id") == message["id"] and "method" not in data:
                            return self.result(data)
                raise ValueError("Missing MCP response")
            body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError("MCP response budget exceeded")
            data = json.loads(body)
            if data.get("id") != message["id"] or "method" in data:
                raise ValueError("Unexpected MCP response identifier")
            return self.result(data)
        finally:
            connection.close()

    @staticmethod
    def result(data):
        if data.get("jsonrpc") != "2.0" or "result" not in data or "error" in data:
            raise ValueError("MCP returned an error or invalid JSON-RPC")
        return data["result"]

    def run(self, name=None, arguments=None):
        initialized = self.request("initialize", {"protocolVersion": self.protocol, "capabilities": {}, "clientInfo": {"name": "argo", "version": "0.2.0"}})
        if initialized.get("protocolVersion") not in {"2024-11-05", "2025-03-26", "2025-06-18"}:
            raise ValueError("Unsupported MCP protocol")
        self.protocol = initialized["protocolVersion"]
        self.request("notifications/initialized", notification=True)
        if name is None:
            result, cursor = [], None
            for _ in range(4):
                page = self.request("tools/list", {"cursor": cursor} if cursor else {})
                result.extend(page["tools"])
                cursor = page.get("nextCursor")
                if not cursor:
                    return {"tools": result}
            raise ValueError("MCP tool pagination budget exceeded")
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768:
            raise ValueError("MCP request too large")
        request = json.loads(raw)
        result = MCP(request["endpoint"]).run(request.get("tool"), request.get("arguments"))
        print(json.dumps({"ok": True, "result": result}))
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)[:500]}))
