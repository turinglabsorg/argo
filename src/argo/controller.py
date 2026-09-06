import hashlib
import json
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

from argo.contracts import Engagement, utc_now
from argo.evidence import EvidenceStore, clean
from argo.inference import analyze, local_models
from argo.intelligence import IntelligenceClient
from argo.network import HTTPBroker
from argo.report import render
from argo.sandbox import scan_snapshot
from argo.scanners import dependencies, finding, read_sources, scan_source
from argo.scope import check_authorization, digest, normalize
from argo.webchecks import validate_web


class Cancelled(Exception):
    pass


def run(
    engagement: Engagement,
    state_root: Path,
    cache: Path | None = None,
    models: list[str] | None = None,
    scanners=False,
    retest: Path | None = None,
    on_progress=None,
    cancelled=lambda: False,
) -> dict:
    engagement = normalize(engagement)
    check_authorization(engagement)
    if models:
        installed = {model["name"] for model in local_models()}
        if set(models) - installed:
            raise RuntimeError(
                "Selected cyber models are not installed locally; run scripts/install_models.py or explicitly use --no-model"
            )
    store = EvidenceStore(state_root, engagement.id, digest(engagement), engagement.limits.max_evidence_mib)
    deadline = time.monotonic() + 1800
    results, packages, gaps, analyses = [], [], [], []
    files_scanned, http_requests = 0, 0
    status = "complete"
    model_requests = 0

    def model_budget():
        nonlocal model_requests
        check()
        if model_requests >= engagement.limits.max_model_actions:
            raise ValueError("Aggregate model action budget exhausted")
        model_requests += 1

    def check():
        if store.cancelled() or cancelled():
            raise Cancelled("Cancellation requested")
        if time.monotonic() >= deadline:
            raise Cancelled("Run deadline reached")
        check_authorization(engagement)

    def progress(stage, **details):
        store.set("status", stage)
        if on_progress:
            on_progress(clean({"run_id": store.run_id, "stage": stage, **details}))

    try:
        check()
        progress("inventory")
        with tempfile.TemporaryDirectory(prefix="argo-snapshot-") as temporary:
            snapshot = Path(temporary)
            snapshot.chmod(0o755)
            originals = []
            for index, root_text in enumerate(
                engagement.scope.repositories if engagement.actions.local_audit else []
            ):
                root = Path(root_text)
                for relative, source, gap in read_sources(root, state_root.resolve(), check):
                    asset = f"repo-{index}/{relative}"
                    if gap:
                        gaps.append(f"{asset}: {gap}")
                        continue
                    found, sanitized, problems = scan_source(asset, source)
                    if scanners:
                        originals.append((asset, source))
                    files_scanned += 1
                    gaps.extend(f"{asset}: {problem}" for problem in problems)
                    target = snapshot / asset
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(sanitized)
                    target.chmod(0o644)
                    for directory in target.parents:
                        if directory == snapshot:
                            break
                        directory.chmod(0o755)
                    inventory_id = store.add(
                        "source_inventory",
                        {
                            "asset": asset,
                            "sanitized_sha256": hashlib.sha256(sanitized.encode()).hexdigest(),
                            "bytes": len(sanitized.encode()),
                        },
                    )
                    for item in found:
                        line = item.line or 1
                        snippet = "\n".join(sanitized.splitlines()[max(0, line - 2) : line + 1])[:4096]
                        evidence_id = store.add(
                            "static_observation",
                            {
                                "asset": asset,
                                "line": line,
                                "rule": item.rule,
                                "excerpt": snippet,
                                "inventory_id": inventory_id,
                            },
                        )
                        item.evidence_ids = [evidence_id]
                    results.extend(found)
                    discovered, problems = dependencies(asset, sanitized)
                    packages.extend(discovered)
                    gaps.extend(f"{asset}: {problem}" for problem in problems)
            if scanners:
                progress("scanners", files=files_scanned)
                extra, scanner_gaps = scan_snapshot(
                    snapshot, store, check, engagement.limits.max_tool_seconds, originals
                )
                results.extend(extra)
                gaps.extend(scanner_gaps)
            else:
                gaps.append(
                    "Semgrep/Gitleaks Docker adapters were not selected; bundled rules provide limited static coverage."
                )
        progress("hypotheses", findings=len(results))
        client = IntelligenceClient(engagement.intelligence, cache or state_root / "intelligence.json", check)
        seen = set()
        for package in packages[:250]:
            check()
            identity = (package.ecosystem, package.name, package.version)
            if identity in seen:
                continue
            seen.add(identity)
            record = client.package(package)
            if record.get("status") != "available":
                gaps.append(
                    f"Dependency intelligence {record.get('status', 'unavailable')} for {package.ecosystem}/{package.name}@{package.version}"
                )
                continue
            data = record.get("data", {})
            if not isinstance(data.get("vulns", []), list):
                gaps.append("Malformed OSV vulnerability list")
                continue
            for vulnerability in data.get("vulns", []):
                if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                    continue
                item = finding(
                    package.asset,
                    None,
                    "osv." + vulnerability["id"],
                    f"Known advisory: {package.name}@{package.version}",
                    None,
                    f"Exact package/version query matched {vulnerability['id']}. Reachability and runtime impact are unverified.",
                    "Review the upstream advisory, upgrade to a fixed compatible version, and retest.",
                )
                item.evidence_ids = [
                    store.add("dependency_intelligence", {"package": package.model_dump(), "record": record})
                ]
                results.append(item)
                for alias in vulnerability.get("aliases", [])[:3]:
                    if isinstance(alias, str) and alias.startswith("CVE-"):
                        enrichment = client.cve(alias)
                        item.evidence_ids.append(
                            store.add("cve_intelligence", {"cve": alias, "sources": enrichment})
                        )
        if len(packages) > 250:
            gaps.append("Dependency enrichment truncated at 250 package records")
        if engagement.actions.web_observe or engagement.actions.web_validate:
            progress("validation", findings=len(results))
            broker = HTTPBroker(engagement, check)
            for endpoint in engagement.scope.web_origins:
                check()
                try:
                    observed = broker.get(endpoint + "/")
                    evidence_id = store.add(
                        "http_observation", {k: v for k, v in observed.items() if k != "body"}
                    )
                    if "content-security-policy" not in observed["headers"] and "text/html" in observed[
                        "headers"
                    ].get("content-type", ""):
                        item = finding(
                            endpoint,
                            None,
                            "argo.http.csp",
                            "HTML response has no Content-Security-Policy",
                            "CWE-693",
                            "The observed HTML response lacks a CSP header. This is a hardening observation, not proof of XSS.",
                            "Define and test a restrictive CSP appropriate to this application.",
                            "low",
                        )
                        item.evidence_ids = [evidence_id]
                        results.append(item)
                    if engagement.actions.web_validate:
                        if observed["headers"].get("x-argo-lab") == "sqlite-fixture-v1":
                            baseline = broker.get(endpoint + "/argo-lab/v1/query?name=guest")
                            probe = broker.get(
                                endpoint + "/argo-lab/v1/query?name=" + quote("' OR 1=1--", safe="")
                            )
                            base_data, probe_data = json.loads(baseline["body"]), json.loads(probe["body"])
                            validation_id = store.add(
                                "controlled_sql_validation",
                                {
                                    "origin": endpoint,
                                    "baseline_rows": base_data["count"],
                                    "probe_rows": probe_data["count"],
                                    "baseline_sha256": baseline["body_sha256"],
                                    "probe_sha256": probe["body_sha256"],
                                },
                            )
                            if base_data["count"] == 1 and probe_data["count"] > 1:
                                item = finding(
                                    endpoint,
                                    None,
                                    "argo.lab.sql-injection",
                                    "SQL injection reproduced in controlled lab",
                                    "CWE-89",
                                    "The seeded lab returns additional synthetic records for the injection probe; the guest control returns one record.",
                                    "Use a parameterized query and rerun the probe/control pair.",
                                )
                                item.status, item.evidence_ids = "confirmed", [validation_id]
                                item.validation = "Known lab protocol; probe changed result cardinality relative to a negative control."
                                results.append(item)
                        else:
                            results.extend(validate_web(endpoint, broker, store))
                            gaps.append(
                                f"{endpoint}: active validation covers CORS behavior and Git HEAD exposure only; application logic and authentication require separate tests"
                            )
                except Cancelled:
                    raise
                except Exception as exc:
                    gaps.append(f"{endpoint}: HTTP check incomplete ({type(exc).__name__})")
            http_requests = broker.requests
        grouped = {}
        for item in results:
            key = (item.asset, item.line, item.cwe) if item.line and item.cwe else item.id
            if key in grouped:
                grouped[key].evidence_ids.extend(item.evidence_ids)
                grouped[key].supporting_rules.append(item.rule)
            else:
                grouped[key] = item
        results = list(grouped.values())
        if models and results:
            for model in models:
                check()
                progress("analysis", model=model, findings=len(results))
                candidates = (
                    [
                        f
                        for f in results
                        if f.asset.startswith("repo-") and f.cwe in {"CWE-89", "CWE-78", "CWE-95", "CWE-79"}
                    ]
                    if "vulnllm" in model
                    else results
                )
                if not candidates:
                    continue
                try:
                    analysis = analyze(
                        model,
                        candidates,
                        min(engagement.limits.max_model_actions, 3),
                        check,
                        store.path / "evidence",
                        model_budget,
                    )
                    analyses.append(analysis)
                    store.add("model_analysis", analysis)
                except Cancelled:
                    raise
                except Exception as exc:
                    gaps.append(f"Local analyst {model} unavailable or incomplete ({type(exc).__name__})")
        else:
            gaps.append("Local model analysis was not selected or there were no findings to analyze.")
        gaps.append(
            "No general network scanner, authenticated API workflow, Nuclei or ZAP execution is enabled in this release."
        )
    except (Cancelled, KeyboardInterrupt):
        status = "cancelled"
        gaps.append("Run stopped before completing all checks")
    except Exception as exc:
        status = "failed"
        gaps.append(f"Run failed ({type(exc).__name__}); partial evidence retained")
    data = clean(
        {
            "run_id": store.run_id,
            "engagement_id": engagement.id,
            "scope_sha256": digest(engagement),
            "created_at": utc_now(),
            "status": status,
            "files_scanned": files_scanned,
            "http_requests": http_requests,
            "model_requests": model_requests,
            "packages": [p.model_dump() for p in packages],
            "findings": [r.model_dump() for r in results],
            "coverage_gaps": gaps,
            "analysis": analyses,
        }
    )
    if retest:
        previous = json.loads((retest / "report.json").read_text())
        before = {item["id"] for item in previous["findings"]}
        now = {item["id"] for item in data["findings"]}
        data["retest"] = {
            "previous_run": previous["run_id"],
            "not_detected": sorted(before - now),
            "persistent": sorted(before & now),
            "new": sorted(now - before),
            "note": "Not detected does not mean fixed; compare scope, scanner coverage and validation evidence.",
        }
    store.set("status", status)
    store.set("finding_count", len(results))
    store.set("finished_at", utc_now())
    try:
        render(store.path, data)
        store.manifest()
    except Exception:
        status = "failed"
        store.set("status", "failed")
        store.event("report_error", {"reason": "Report or manifest could not be persisted"})
    finally:
        store.close()
    return {
        "run_id": store.run_id,
        "status": status,
        "findings": len(results),
        "report": str(store.path / "report.md"),
    }
