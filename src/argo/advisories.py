import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from argo.contracts import Disclosure, Intelligence
from argo.conversation import save_checkpoint
from argo.evidence import clean, private_dir
from argo.intelligence import IntelligenceClient

SETTINGS = Path.home() / ".argo" / "intelligence-settings.json"
ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{3,119}\Z")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def load_mode(path=None):
    path = path or SETTINGS
    if not path.exists():
        return "offline"
    if path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError("Invalid vulnerability intelligence settings")
    mode = json.loads(path.read_text()).get("mode")
    if mode not in {"offline", "connected"}:
        raise ValueError("Invalid vulnerability intelligence mode")
    return mode


def save_mode(mode, path=None):
    if mode not in {"offline", "connected"}:
        raise ValueError("Choose offline or connected")
    path = path or SETTINGS
    private_dir(path.parent)
    save_checkpoint(path, {"mode": mode})


def safe_url(value):
    if not isinstance(value, str) or len(value) > 2000:
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme in {"https", "http"} and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        return False


def severity(value):
    value = str(value).lower()
    return value if value in {"critical", "high", "medium", "low"} else "info"


def valid_osv_record(data):
    if not isinstance(data, dict) or not isinstance(data.get("affected"), list):
        return False
    if not isinstance(data.get("aliases", []), list) or not isinstance(data.get("references", []), list) or not isinstance(data.get("database_specific", {}), dict):
        return False
    for item in data["affected"]:
        if not isinstance(item, dict) or not isinstance(item.get("package"), dict) or not isinstance(item.get("ranges", []), list):
            return False
        if not isinstance(item["package"].get("name"), str):
            return False
        if any(not isinstance(interval, dict) or not isinstance(interval.get("events", []), list) for interval in item.get("ranges", [])):
            return False
    return True


def package_name(name, ecosystem):
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


class AdvisoryService:
    def __init__(self, cache, mode="offline", check=lambda: None, progress=lambda _: None):
        if mode not in {"offline", "connected"}:
            raise ValueError("Invalid intelligence mode")
        self.mode, self.cache, self.check, self.progress = mode, Path(cache), check, progress
        policy = Intelligence(mode=mode, providers=["osv", "nvd", "epss", "cisa_kev"], disclosure=Disclosure(cve_ids=True, public_package_versions=True))
        self.client = IntelligenceClient(policy, self.cache, check)

    def request(self, provider, path, payload=None, ttl=86400):
        self.check()
        key = hashlib.sha256(json.dumps([provider, path, payload], sort_keys=True).encode()).hexdigest()
        location = self.cache / (key + ".json")
        cached = None
        if not self.cache.is_symlink() and location.is_file() and not location.is_symlink() and location.stat().st_size <= 8 * 1024**2:
            try:
                cached = json.loads(location.read_text())
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(cached["retrieved_at"])).total_seconds()
                if cached.get("provider") != provider or not isinstance(cached.get("data"), dict) or age < -60:
                    cached = None
                elif age <= ttl:
                    return {**cached, "cached": True, "status": "available"}
            except (ValueError, TypeError, KeyError, OSError):
                cached = None
        if self.mode == "connected":
            self.progress("Querying " + provider.upper())
            record = self.client.request(provider, path, payload)
            if record.get("status") == "available":
                private_dir(self.cache)
                save_checkpoint(location, record)
                return record
            if cached:
                return {**cached, "cached": True, "status": "stale", "refresh_status": record["status"]}
            return record
        if cached:
            return {**cached, "cached": True, "status": "stale"}
        return {"status": "unavailable", "provider": provider, "reason": "No cached record; intelligence is offline"}

    def osv_queries(self, packages, gaps):
        matches = {}
        for offset in range(0, len(packages), 100):
            pending = [(package, {"package": {"ecosystem": package["ecosystem"], "name": package["name"]}, "version": package["version"]}) for package in packages[offset:offset + 100]]
            for _ in range(5):
                if not pending:
                    break
                result = self.request("osv", "/v1/querybatch", {"queries": [query for _, query in pending]})
                rows = result.get("data", {}).get("results")
                if result["status"] not in {"available", "stale"} or not isinstance(rows, list) or len(rows) != len(pending):
                    gaps.append("OSV package query unavailable or malformed; this is not a negative result")
                    break
                if result["status"] == "stale":
                    gaps.append("OSV package matches are stale; freshness could not be established")
                following = []
                for (package, query), row in zip(pending, rows, strict=True):
                    if not isinstance(row, dict) or not isinstance(row.get("vulns", []), list):
                        gaps.append("OSV returned an invalid package result")
                        continue
                    key = (package["ecosystem"], package["name"], package["version"])
                    match = matches.setdefault(key, {"package": package, "ids": set(), "status": result["status"], "retrieved_at": result.get("retrieved_at")})
                    if result["status"] == "stale":
                        match["status"] = "stale"
                    for item in row.get("vulns", []):
                        identity = item.get("id") if isinstance(item, dict) else None
                        if isinstance(identity, str) and ADVISORY_ID.fullmatch(identity):
                            match["ids"].add(identity)
                        else:
                            gaps.append("OSV returned an invalid advisory identifier")
                    token = row.get("next_page_token")
                    if token:
                        if isinstance(token, str) and len(token) <= 4096:
                            following.append((package, {**query, "page_token": token}))
                        else:
                            gaps.append("OSV returned an invalid pagination token")
                pending = following
            if pending and result.get("data", {}).get("results"):
                gaps.append("OSV pagination was incomplete")
        return matches

    def enrich(self, identities, include_nvd=False):
        identities = sorted(set(identity for identity in identities if CVE_ID.fullmatch(identity)))[:100]
        if not identities:
            return {}
        epss = self.request("epss", "/data/v1/epss?" + urlencode({"cve": ",".join(identities)}))
        kev = self.request("cisa_kev", "/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        rows = epss.get("data", {}).get("data")
        entries = kev.get("data", {}).get("vulnerabilities")
        scores = {row.get("cve"): row for row in rows if isinstance(row, dict)} if isinstance(rows, list) else {}
        exploited = {row.get("cveID") for row in entries if isinstance(row, dict)} if isinstance(entries, list) else set()
        results = {}
        for identity in identities:
            score = scores.get(identity)
            value = {
                "epss": {"status": epss["status"] if score else "unavailable", "data": score, "retrieved_at": epss.get("retrieved_at"), "source": epss.get("source")},
                "kev": {"status": kev["status"] if isinstance(entries, list) else "unavailable", "in_kev": identity in exploited if isinstance(entries, list) else None, "retrieved_at": kev.get("retrieved_at"), "source": kev.get("source")},
            }
            if include_nvd:
                record = self.request("nvd", "/rest/json/cves/2.0?" + urlencode({"cveId": identity}))
                records = record.get("data", {}).get("vulnerabilities")
                matched = next((row["cve"] for row in records if isinstance(row, dict) and isinstance(row.get("cve"), dict) and row["cve"].get("id") == identity), None) if isinstance(records, list) else None
                value["nvd"] = {"status": record["status"] if matched else "unavailable", "source": record.get("source"), "retrieved_at": record.get("retrieved_at"), "data": matched}
            results[identity] = value
        return results

    def scan(self, project):
        gaps = list(project["coverage_gaps"])
        unique = {}
        locations = {}
        for package in project["packages"]:
            if not package["public"]:
                continue
            key = (package["ecosystem"], package["name"], package["version"])
            unique[key] = package
            locations.setdefault(key, []).append(package["path"])
        matches = self.osv_queries(list(unique.values()), gaps)
        total_ids = set().union(*(match["ids"] for match in matches.values())) if matches else set()
        selected = sorted(total_ids)[:100]
        if len(total_ids) > len(selected):
            gaps.append("Advisory detail coverage truncated at 100 records")
        details = {}
        for identity in selected:
            self.check()
            response = self.request("osv", "/v1/vulns/" + quote(identity, safe=""))
            data = response.get("data", {})
            if response["status"] not in {"available", "stale"} or not valid_osv_record(data) or data.get("id") != identity:
                gaps.append(identity + ": advisory details unavailable or malformed")
                continue
            if data.get("withdrawn"):
                gaps.append(identity + ": withdrawn advisory excluded")
                continue
            details[identity] = (response, data)
        candidates = []
        for key, match in matches.items():
            for identity in sorted(match["ids"] & details.keys()):
                response, data = details[identity]
                package = match["package"]
                affected = [item for item in data["affected"] if item["package"].get("ecosystem") == package["ecosystem"] and package_name(item["package"]["name"], package["ecosystem"]) == package_name(package["name"], package["ecosystem"])]
                if not affected:
                    gaps.append(identity + ": returned package identity does not match the inventory query")
                    continue
                fixed = sorted({event["fixed"] for item in affected for interval in item.get("ranges", []) if isinstance(interval, dict) for event in interval.get("events", []) if isinstance(event, dict) and isinstance(event.get("fixed"), str)})
                candidates.append({
                    "id": hashlib.sha256(json.dumps([key, identity]).encode()).hexdigest()[:16],
                    "advisory_id": identity, "cve_ids": list(dict.fromkeys(alias for alias in [identity, *data.get("aliases", [])] if isinstance(alias, str) and CVE_ID.fullmatch(alias))),
                    "package": {field: package[field] for field in ("ecosystem", "name", "version", "path", "version_source", "usage_paths", "declared_groups")},
                    "locations": sorted(set(locations[key])), "match": "OSV exact package/version query",
                    "summary": str(data.get("summary") or identity)[:500], "details": str(data.get("details", ""))[:6000],
                    "severity": severity(data.get("database_specific", {}).get("severity")),
                    "fixed_versions": fixed[:20], "affected": affected,
                    "references": [item["url"] for item in data.get("references", []) if isinstance(item, dict) and safe_url(item.get("url"))][:10],
                    "source": response.get("source"), "retrieved_at": response.get("retrieved_at"), "modified": data.get("modified"), "published": data.get("published"),
                    "freshness": "stale" if "stale" in {match["status"], response["status"]} else "available",
                    "assessment": "needs_review", "exploitability": "unverified",
                })
        for technology in project["technologies"]:
            if not technology.get("cpe"):
                continue
            record = self.request("nvd", "/rest/json/cves/2.0?" + urlencode({"cpeName": technology["cpe"], "resultsPerPage": 20}))
            rows = record.get("data", {}).get("vulnerabilities")
            if record["status"] not in {"available", "stale"} or not isinstance(rows, list):
                gaps.append(technology["name"] + ": NVD CPE lookup unavailable")
                continue
            total = record.get("data", {}).get("totalResults", 0)
            if not isinstance(total, int) or total > len(rows):
                gaps.append(technology["name"] + ": NVD CPE results truncated")
            for row in rows:
                cve = row.get("cve", {}) if isinstance(row, dict) else {}
                if not isinstance(cve, dict) or any(not isinstance(cve.get(field, []), list) or any(not isinstance(item, dict) for item in cve.get(field, [])) for field in ("descriptions", "references")):
                    gaps.append(technology["name"] + ": malformed NVD record excluded")
                    continue
                identity = cve.get("id", "")
                if not isinstance(identity, str) or not CVE_ID.fullmatch(identity):
                    continue
                description = str(next((item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"), ""))
                candidates.append({"id": hashlib.sha256((technology["cpe"] + identity).encode()).hexdigest()[:16], "advisory_id": identity, "cve_ids": [identity], "package": {"name": technology["name"], "version": technology["version"], "path": technology["path"], "ecosystem": "CPE", "usage_paths": []}, "locations": [technology["path"]], "match": "NVD CPE candidate; configuration conditions require review", "summary": description[:500], "details": description[:6000], "severity": "info", "fixed_versions": [], "references": [item["url"] for item in cve.get("references", []) if safe_url(item.get("url"))][:10], "affected": cve.get("configurations", []), "source": record.get("source"), "retrieved_at": record.get("retrieved_at"), "modified": cve.get("lastModified"), "published": cve.get("published"), "freshness": record["status"], "assessment": "needs_review", "exploitability": "unverified"})
        enrichment = self.enrich([identity for candidate in candidates for identity in candidate["cve_ids"]])
        for candidate in candidates:
            candidate["intelligence"] = {identity: enrichment.get(identity, {}) for identity in candidate["cve_ids"]}
            if any(value.get("kev", {}).get("status") != "available" or value.get("epss", {}).get("status") != "available" for value in candidate["intelligence"].values()):
                gaps.append("Some EPSS or KEV records are unavailable or stale")
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        candidates.sort(key=lambda c: (any(value.get("kev", {}).get("in_kev") is True for value in c["intelligence"].values()), order[c["severity"]], bool(c["package"]["usage_paths"])), reverse=True)
        if len(candidates) > 200:
            gaps.append("Candidate coverage truncated at 200 package/advisory matches")
        return clean({"mode": self.mode, "status": "partial" if gaps or len(matches) != len(unique) else "complete", "inventory_fingerprint": project["fingerprint"], "packages_total": len(project["packages"]), "packages_queried": len(matches), "public_packages": len(unique), "candidates": candidates[:200], "coverage_gaps": list(dict.fromkeys(gaps)), "note": "Advisory matching does not prove runtime reachability or exploitability. Empty results with gaps are not a clean bill of health."})


def review_context(catalog, paths, selected=None):
    candidates = catalog.get("candidates", [])
    if selected:
        known = {item["id"] for item in candidates}
        if set(selected) - known:
            raise ValueError("Choose candidate IDs from security.cves")
        candidates = [item for item in candidates if item["id"] in selected]
    else:
        candidates = sorted(candidates, key=lambda item: bool(set(paths) & set([*item["locations"], *item["package"]["usage_paths"]])), reverse=True)[:3]
    if not candidates:
        return None
    return {"advisories": [{key: item[key] for key in ("id", "advisory_id", "cve_ids", "package", "match", "summary", "severity", "fixed_versions", "freshness")} | {"details": item["details"][:1800], "references": item["references"][:3]} for item in candidates], "note": "Untrusted source records. Check actual usage, affected versions, prerequisites and mitigations. Describe a bounded local positive/negative test. Do not equate a CVE match or model agreement with exploitability."}
