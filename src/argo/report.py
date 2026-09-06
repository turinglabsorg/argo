import html
import json

from argo.evidence import clean, write_private


def text(value):
    return (
        html.escape(str(value)).replace("`", "'").replace("\n", " ").replace("[", "\\[").replace("]", "\\]")
    )


def render(path, data):
    data = clean(data)
    write_private(path / "report.json", json.dumps(data, indent=2) + "\n")
    lines = [
        f"# Argo report: {text(data['engagement_id'])}",
        "",
        f"Run: `{data['run_id']}` · Status: **{text(data['status'])}**",
        "",
        f"Scope digest: `{data['scope_sha256']}`",
        "",
        "Static signals remain suspected unless a separate controlled validation confirms them.",
        "",
        f"Files inspected: {data['files_scanned']} · Packages inventoried: {len(data['packages'])} · Findings: {len(data['findings'])}",
        "",
    ]
    for item in data["findings"]:
        lines += [
            f"## {text(item['title'])}",
            "",
            f"**{item['severity'].upper()} · {item['status']}** — `{text(item['asset'])}`"
            + (f":{item['line']}" if item.get("line") else ""),
            "",
            text(item["explanation"]),
            "",
            f"Remediation: {text(item['remediation'])}",
            "",
            "Evidence: "
            + ", ".join(f"[{identity[:12]}](evidence/{identity}.json)" for identity in item["evidence_ids"]),
            "",
        ]
        if item.get("validation"):
            lines += [f"Validation: {text(item['validation'])}", ""]
    if data.get("analysis"):
        lines += ["## Local model analysis", ""]
        for analysis in data["analysis"]:
            lines += [f"Model: `{text(analysis['model'])}` · status: {text(analysis['status'])}", ""]
            for proposal in analysis.get("proposals", []):
                lines += [
                    f"- `{text(proposal['finding_id'])}`: {text(proposal['explanation'])} Next check: {text(proposal['next_check'])}"
                ]
            lines += [""]
    lines += ["## Coverage and limitations", ""]
    lines += [f"- {text(gap)}" for gap in sorted(set(data["coverage_gaps"]))]
    if data.get("retest"):
        lines += [
            "",
            "## Retest comparison",
            "",
            text(data["retest"]["note"]),
            "",
            f"Previously observed findings no longer detected: {len(data['retest']['not_detected'])}.",
        ]
    write_private(path / "report.md", "\n".join(lines) + "\n")
