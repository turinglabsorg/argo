import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from argo.contracts import Intelligence, Package, utc_now

ORIGINS = {
    "osv": "https://api.osv.dev",
    "nvd": "https://services.nvd.nist.gov",
    "epss": "https://api.first.org",
    "cisa_kev": "https://www.cisa.gov",
}


class IntelligenceClient:
    def __init__(self, policy: Intelligence, cache: Path, check=lambda: None):
        self.policy, self.cache, self.check = policy, cache, check
        self.last_nvd = 0.0

    def request(self, provider: str, path: str, payload=None) -> dict:
        self.check()
        if self.policy.mode != "connected" or provider not in self.policy.providers:
            return {"status": "unavailable", "provider": provider, "reason": "Provider is disabled"}
        if provider == "nvd":
            wait = max(0, 6.1 - (time.monotonic() - self.last_nvd))
            for _ in range(int(wait / 0.1) + 1):
                self.check()
                if time.monotonic() - self.last_nvd >= 6.1:
                    break
                time.sleep(0.1)
            self.last_nvd = time.monotonic()
        url = ORIGINS[provider] + path
        deadline = time.monotonic() + 20
        try:
            with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
                with client.stream("POST" if payload is not None else "GET", url, json=payload) as response:
                    if response.status_code == 429:
                        return {"status": "rate_limited", "provider": provider}
                    response.raise_for_status()
                    chunks, total = [], 0
                    for chunk in response.iter_bytes():
                        self.check()
                        if time.monotonic() > deadline:
                            raise ValueError("Provider response deadline exceeded")
                        total += len(chunk)
                        if total > 8 * 1024 * 1024:
                            raise ValueError("Oversized provider response")
                        chunks.append(chunk)
            data = json.loads(b"".join(chunks))
            if not isinstance(data, dict):
                raise ValueError("Invalid provider response")
            return {
                "status": "available",
                "provider": provider,
                "retrieved_at": utc_now(),
                "source": url,
                "data": data,
            }
        except (httpx.HTTPError, ValueError):
            return {
                "status": "unavailable",
                "provider": provider,
                "reason": "Provider request failed or response invalid",
            }

    def package(self, package: Package) -> dict:
        cache_key = f"{package.ecosystem}/{package.name}@{package.version}"
        if self.cache.is_file():
            if self.cache.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("Oversized intelligence cache")
            recorded = json.loads(self.cache.read_text())
            if cache_key in recorded.get("packages", {}):
                record = recorded["packages"][cache_key]
                result = dict(record)
                try:
                    age = datetime.now(timezone.utc) - datetime.fromisoformat(record["retrieved_at"])
                    result["status"] = "stale" if age.days > 7 else "available"
                except (KeyError, ValueError, TypeError):
                    result["status"] = "stale"
                result["cached"] = True
                return result
        if not self.policy.disclosure.public_package_versions:
            return {"status": "unavailable", "reason": "No cached record; package disclosure disabled"}
        return self.request(
            "osv",
            "/v1/query",
            {"package": {"name": package.name, "ecosystem": package.ecosystem}, "version": package.version},
        )

    def cve(self, cve_id: str) -> list[dict]:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("Invalid CVE identifier")
        if not self.policy.disclosure.cve_ids:
            return [{"status": "unavailable", "reason": "CVE disclosure disabled"}]
        results = []
        if "nvd" in self.policy.providers:
            results.append(self.request("nvd", f"/rest/json/cves/2.0?cveId={cve_id}"))
        if "epss" in self.policy.providers:
            results.append(self.request("epss", f"/data/v1/epss?cve={cve_id}"))
        if "cisa_kev" in self.policy.providers:
            result = self.request(
                "cisa_kev", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            if result.get("status") == "available":
                entries = result["data"].get("vulnerabilities")
                if not isinstance(entries, list):
                    result = {"status": "unavailable", "provider": "cisa_kev", "reason": "Catalog missing"}
                else:
                    result["data"] = {"cve": cve_id, "in_kev": any(e.get("cveID") == cve_id for e in entries)}
            results.append(result)
        return results
