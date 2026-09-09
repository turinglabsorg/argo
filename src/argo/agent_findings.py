import hashlib
import json

from argo.contracts import Finding
from argo.evidence import clean, read_evidence
from argo.finding_review import apply_review
from argo.finding_validation import apply_result, selected_finding
from argo.workspace import validate_path

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "path": {"type": "string", "minLength": 1, "maxLength": 240},
        "line": {"type": ["integer", "null"], "minimum": 1},
        "severity": {"enum": ["info", "low", "medium", "high", "critical"]},
        "explanation": {"type": "string", "minLength": 1, "maxLength": 3000},
        "remediation": {"type": "string", "minLength": 1, "maxLength": 2000},
        "evidence_ids": {"type": "array", "minItems": 1, "maxItems": 10, "uniqueItems": True, "items": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
    },
    "required": ["title", "path", "severity", "explanation", "remediation", "evidence_ids"],
    "additionalProperties": False,
}


def proposed_finding(value, evidence_id, rule="agent.observation"):
    if not isinstance(value, dict):
        raise ValueError("Finding must be an object")
    asset = value.get("path", value.get("file", ""))
    title = value.get("title", value.get("issue", value.get("titolo", "")))
    if not isinstance(asset, str) or not isinstance(title, str) or not title.strip():
        raise ValueError("Finding requires a source path and title")
    asset = validate_path(asset.split(",")[0].strip())
    identity = hashlib.sha256(f"{rule}:{asset}:{title}".encode()).hexdigest()[:16]
    explanation = value.get("explanation", value.get("evidenza", title))
    severity = value.get("severity", "info")
    line = value.get("line")
    return Finding(
        id=identity, asset=asset, rule=rule, title=title[:200],
        severity=severity, status="suspected", line=line,
        evidence_ids=list(dict.fromkeys([evidence_id, *value.get("evidence_ids", [])])),
        explanation=str(explanation)[:3000],
        remediation=str(value.get("remediation", "Validate the observation with a controlled runtime test, then select a targeted fix."))[:2000],
        validation="Model or script observation. Tool execution and passing generated tests do not establish exploitability. Severity is unassessed when shown as info.",
    ).model_dump()


def tool_findings(data, evidence_id):
    tool = data.get("action", {}).get("tool")
    result = data.get("result", {})
    if not isinstance(result, dict):
        return []
    if tool == "security.review":
        values = result.get("suspected_findings", [])
    elif tool == "security.cves":
        return [Finding(
            id=item["id"], asset=validate_path(item["package"]["path"]), rule="agent.cve",
            title=f"{', '.join(item['cve_ids']) or item['advisory_id']}: {item['package']['name']}@{item['package']['version']}"[:200],
            severity=item["severity"], status="suspected", evidence_ids=[evidence_id],
            explanation=(item["match"] + ". " + item["summary"] + "\n" + item["details"])[:3000],
            remediation="Review applicability and the upstream advisory. Reported fixed versions: " + (", ".join(item["fixed_versions"]) or "consult the advisory") + ". Verify compatibility and rerun regression tests.",
            validation="CVE candidate; runtime reachability and exploitability are unverified. Source freshness: " + item["freshness"],
            advisory_ids=list(dict.fromkeys([item["advisory_id"], *item["cve_ids"]])),
        ).model_dump() for item in result.get("candidates", [])]
    elif tool == "findings.record":
        values = result.get("findings", [])
    elif tool == "python.run" and result.get("exit_code") == 0:
        try:
            output = json.loads(result.get("stdout", ""))
        except (ValueError, TypeError):
            return []
        values = output.get("findings", []) if isinstance(output, dict) else []
    else:
        return []
    if not isinstance(values, list):
        return []
    findings = []
    for value in values[:100]:
        try:
            # Only the executed tool record supplies evidence; its text cannot cite other records.
            value = {**value, "evidence_ids": []}
            if value.get("verdict") == "mitigato":
                continue
            findings.append(proposed_finding(value, evidence_id, "agent." + tool))
        except (ValueError, TypeError):
            continue
    return clean(findings)


def merge_findings(existing, additional):
    merged = {item["id"]: item for item in existing}
    for item in additional:
        if item["id"] in merged:
            item = {**item, "evidence_ids": list(dict.fromkeys([*merged[item["id"]]["evidence_ids"], *item["evidence_ids"]])), "assessments": merged[item["id"]].get("assessments", []) + item.get("assessments", [])}
            item["verification"] = merged[item["id"]].get("verification", item.get("verification"))
            if (item["verification"].get("test_evidence_id") or item["verification"].get("reviews")) and any(item[key] != merged[item["id"]][key] for key in ("asset", "title", "explanation", "remediation")):
                item["verification"] = {**item["verification"], "state": "stale", "explanation": "The tested claim changed. Retest under the current review policy."}
            if item["rule"] == "agent.cve":
                item["validation"] = merged[item["id"]]["validation"]
        merged[item["id"]] = item
    return list(merged.values())


def apply_cve_reviews(findings, result, evidence_id):
    indexed = {item["id"]: item for item in findings}
    for assessment in result.get("cve_assessments", []):
        if assessment["candidate_id"] not in indexed:
            continue
        item = indexed[assessment["candidate_id"]]
        value = {key: assessment[key] for key in ("assessment", "reason", "prerequisites", "test_plan")}
        value.update(model=result["model"], evidence_id=evidence_id)
        item.setdefault("assessments", []).append(value)
        item["evidence_ids"] = list(dict.fromkeys([*item["evidence_ids"], evidence_id]))
        previous_runtime = item.get("validation", "").partition("\n\nRuntime evidence attached.")
        item["validation"] = "Model applicability assessments; exploitability remains unverified.\n" + "\n\n".join(
            f"{review['model']}: {review['assessment']}\n{review['reason']}\nPrerequisites: {review['prerequisites']}\nLocal test: {review['test_plan']}"
            for review in item["assessments"]
        )
        if previous_runtime[1]:
            item["validation"] += previous_runtime[1] + previous_runtime[2]
    return list(indexed.values())


def load_agent_findings(path, report):
    if report.get("kind") != "isolated_agent" or report.get("findings"):
        return report.get("findings", [])
    findings = []
    for event in report.get("tools", []):
        tool = event.get("tool")
        mutating = tool in {"code.edit", "python.run", "python.tests", "node.tests", "project.tests", "findings.test"}
        if not mutating and tool not in {"security.review", "security.cves", "findings.record", "findings.verdict", "findings.defer"}:
            continue
        identity = event["evidence_id"]
        record = read_evidence(path, identity)
        if record.get("kind") != "agent_tool":
            continue
        if mutating:
            invalidated = record["data"].get("verification_invalidated")
            for item in findings:
                if (item.get("verification") or {}).get("test_evidence_id") and (invalidated is None or item["id"] in invalidated):
                    explanation = "Recovered validation preceded a potentially mutating tool. Retest the current workspace." if invalidated is None else "Source or associated tests changed after validation. Run findings.test again."
                    item["verification"].update(state="stale", explanation=explanation)
        if record.get("kind") == "agent_tool":
            findings = merge_findings(findings, tool_findings(record["data"], identity))
            if event.get("tool") == "security.review":
                findings = apply_cve_reviews(findings, record["data"]["result"], identity)
                apply_review(findings, record["data"]["result"], identity)
            if event.get("tool") in {"findings.test", "findings.verdict", "findings.defer"}:
                result = record["data"]["result"]
                apply_result(selected_finding(findings, result["finding_id"]), event["tool"], result, identity)
    return findings
