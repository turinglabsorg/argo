import hashlib
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

from argo.contracts import Engagement
from argo.scope import ScopeError, check_authorization, check_path, origin

MANAGEMENT_PORTS = {22, 2375, 2376, 11434}
PROBE_ORIGIN = "https://argo-cors-probe.invalid"
EVIDENCE_HEADERS = {
    "content-type",
    "content-length",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "x-argo-lab",
    "server",
}


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)
        if ipaddress.ip_address(self.sock.getpeername()[0]) != ipaddress.ip_address(self.address):
            self.close()
            raise ScopeError("Connected peer differs from approved address")


class PinnedHTTPS(PinnedHTTP):
    def connect(self):
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


class HTTPBroker:
    def __init__(self, engagement: Engagement, check=lambda: None):
        self.engagement = engagement
        self.check = check
        self.requests = 0
        self.last = {}
        self.deadline = time.monotonic() + engagement.limits.max_tool_seconds

    def get(self, url: str, redirects: int = 3, cors_probe=False) -> dict:
        self.check()
        check_authorization(self.engagement)
        if not (self.engagement.actions.web_observe or self.engagement.actions.web_validate):
            raise ScopeError("Web actions are not enabled")
        parsed = urlsplit(url)
        endpoint = origin(f"{parsed.scheme}://{parsed.netloc}")
        if endpoint not in self.engagement.scope.web_origins:
            raise ScopeError("HTTP origin is outside the authorized scope")
        if parsed.username is not None or parsed.fragment or "GET" not in self.engagement.scope.http_methods:
            raise ScopeError("Request credentials, fragments, or method are not permitted")
        check_path(parsed.path or "/", self.engagement.scope.excluded_path_prefixes)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        if port in MANAGEMENT_PORTS:
            raise ScopeError("Host management service is never a web target")
        addresses = {info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        if not addresses:
            raise ScopeError("Target did not resolve")
        for item in addresses:
            address = ipaddress.ip_address(item)
            mapped = getattr(address, "ipv4_mapped", None)
            address = mapped or address
            if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise ScopeError("Forbidden network address")
            if address.is_private:
                if host == "localhost" and address.is_loopback:
                    continue
                try:
                    if ipaddress.ip_address(host) == address:
                        continue
                except ValueError:
                    pass
                raise ScopeError("Private targets must be explicitly scoped by IP")
        if self.requests >= self.engagement.limits.max_total_target_requests:
            raise ScopeError("Aggregate target request budget exhausted")
        pause = 1 / self.engagement.limits.max_requests_per_second_per_target - (
            time.monotonic() - self.last.get(endpoint, 0)
        )
        while pause > 0:
            self.check()
            time.sleep(min(pause, 0.05))
            pause -= 0.05
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ScopeError("HTTP adapter deadline exceeded")
        self.requests += 1
        self.last[endpoint] = time.monotonic()
        cls = PinnedHTTPS if parsed.scheme == "https" else PinnedHTTP
        connection = cls(host, port, sorted(addresses)[0], min(5, remaining))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        expired = threading.Event()

        def interrupt_socket():
            expired.set()
            if connection.sock:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(min(5, remaining), interrupt_socket)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "User-Agent": "Argo-Security/0.1",
                    "Accept": "application/json,text/html",
                    "Accept-Encoding": "identity",
                    **({"Origin": PROBE_ORIGIN} if cors_probe else {}),
                },
            )
            response = connection.getresponse()
            body = response.read(65537)
            headers = {
                k.lower(): v
                for k, v in response.getheaders()
                if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
            }
            status = response.status
        finally:
            watchdog.cancel()
            connection.close()
        self.check()
        if expired.is_set():
            raise ScopeError("HTTP request deadline exceeded")
        if status in {301, 302, 303, 307, 308} and "location" in headers:
            if redirects <= 0:
                raise ScopeError("Redirect budget exhausted")
            return self.get(urljoin(url, headers["location"]), redirects - 1, cors_probe)
        if len(body) > 65536:
            raise ScopeError("HTTP response exceeds evidence limit")
        return {
            "url": url,
            "status": status,
            "headers": {k: v for k, v in headers.items() if k in EVIDENCE_HEADERS},
            "body": body,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "peer_ip": sorted(addresses)[0],
        }
