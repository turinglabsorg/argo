import hashlib
import json

from argo.contracts import Finding
from argo.evidence import clean, read_evidence
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
            item = {**item, "evidence_ids": list(dict.fromkeys([*merged[item["id"]]["evidence_ids"], *item["evidence_ids"]]))}
        merged[item["id"]] = item
    return list(merged.values())


def load_agent_findings(path, report):
    if report.get("kind") != "isolated_agent" or report.get("findings"):
        return report.get("findings", [])
    findings = []
    for event in report.get("tools", []):
        if event.get("tool") not in {"security.review", "findings.record", "python.run"}:
            continue
        identity = event["evidence_id"]
        record = read_evidence(path, identity)
        if record.get("kind") == "agent_tool":
            findings = merge_findings(findings, tool_findings(record["data"], identity))
    return findings
