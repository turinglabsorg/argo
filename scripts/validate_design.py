import copy
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def main():
    schema = json.loads((ROOT / "schemas/engagement.schema.json").read_text())
    example = json.loads((ROOT / "config/engagement.example.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(example)

    invalid_cases = [
        ("unrecorded authorization", ("authorization", "status"), "authorized"),
        ("invalid timestamp", ("authorization", "approved_at"), "yesterday"),
        ("unknown action", ("actions", "shell"), True),
        ("relative repository", ("scope", "repositories"), ["../outside"]),
        ("credential-bearing origin", ("scope", "web_origins"), ["https://user:pass@example.invalid"]),
        ("origin with path", ("scope", "web_origins"), ["https://example.invalid/admin"]),
        ("unsupported scheme", ("scope", "web_origins"), ["file:///etc/hosts"]),
        ("invalid port", ("scope", "network_ports"), [65536]),
        ("unsupported method", ("scope", "http_methods"), ["CONNECT"]),
        ("offline provider", ("intelligence", "providers"), ["nvd"]),
        ("offline disclosure", ("intelligence", "disclosure", "cve_ids"), True),
        ("target disclosure", ("intelligence", "disclosure", "target_identifiers"), True),
        ("unbounded actions", ("limits", "max_model_actions"), 0),
        ("plaintext credential field", ("credential_refs",), [{"password": "synthetic-test-marker"}]),
    ]
    for label, path, value in invalid_cases:
        candidate = copy.deepcopy(example)
        parent = candidate
        for part in path[:-1]:
            parent = parent[part]
        parent[path[-1]] = value
        if validator.is_valid(candidate):
            raise AssertionError(f"Invalid fixture accepted: {label}")

    contract = json.loads((ROOT / "config/intelligence.contract.json").read_text())
    if contract["enabled"] or example["authorization"]["status"] != "draft":
        raise AssertionError("Design examples must remain disabled/draft")
    if not re.fullmatch(r"[a-f0-9]{40}", contract["upstream"]["revision"]):
        raise AssertionError("Upstream source review must name a full commit hash")

    links_checked = 0
    for document in [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]:
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", document.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            local = target.split("#", 1)[0]
            if not (document.parent / local).is_file():
                raise AssertionError(f"Broken local link in {document.name}: {target}")
            links_checked += 1

    print(f"Schema and draft example valid; {len(invalid_cases)} denial fixtures rejected.")
    print(f"Intelligence contract disabled and pinned; {links_checked} local document links valid.")
    print("Structural validation only; runtime integration tests are separate.")


if __name__ == "__main__":
    main()
