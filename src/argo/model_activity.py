import json
import re

from argo.evidence import redact

FIELDS = re.compile(r'"(summary|path|issue|remediation|explanation|next_check)"\s*:\s*("(?:[^"\\]|\\.)*)')
LABELS = {"path": "File: ", "issue": "Suspected issue: ", "remediation": "Suggested fix: ", "next_check": "Next check: "}


def analysis_text(content):
    parts = []
    for match in FIELDS.finditer(content):
        try:
            value = json.loads(match[2] + '"')
        except ValueError:
            continue
        if value:
            parts.append(LABELS.get(match[1], "") + value)
    return redact("\n\n".join(parts))[:16000]


def review_text(result):
    if not result.get("finding_review"):
        return analysis_text(json.dumps(result))
    heading = result["finding_review"]["phase"].capitalize() + " review · " + result["decision"]
    return redact("\n\n".join([heading, result["summary"], result.get("test_assessment", ""), *result.get("remaining_concerns", [])]))[:16000]
