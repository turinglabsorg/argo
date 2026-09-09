import hashlib
from collections import Counter
from pathlib import PurePosixPath

from argo.contracts import FindingVerification
from argo.workspace import validate_path

ROLES = ("positive_control", "negative_control", "regression")
RESOLVED = {"reproduced", "refuted", "fixed", "inconclusive"}
PATH = {"type": "string", "minLength": 1, "maxLength": 240}
IDENTITY = {"type": "string", "pattern": "^[a-f0-9]{16}$"}
EVIDENCE = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 2000}


def contract(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


TOOLS = {
    "findings.list": contract({"offset": {"type": "integer", "minimum": 0}}),
    "findings.test": contract({
        "finding_id": IDENTITY,
        "hypothesis": TEXT,
        "expected_secure_behavior": TEXT,
        "source_paths": {"type": "array", "items": PATH, "minItems": 1, "maxItems": 20, "uniqueItems": True},
        "tests": contract({role: PATH for role in ROLES}),
    }),
    "findings.verdict": contract({
        "finding_id": IDENTITY, "test_evidence_id": EVIDENCE,
        "interpretation": {"enum": ["reproduced", "refuted", "fixed", "inconclusive"]},
        "explanation": TEXT,
    }),
    "findings.defer": contract({
        "finding_id": IDENTITY, "reason": TEXT, "required_prerequisite": TEXT,
        "evidence_ids": {"type": "array", "items": EVIDENCE, "minItems": 1, "maxItems": 5, "uniqueItems": True},
    }),
}

GUIDANCE = """
Every finding, including reviewer observations and database candidates, enters a mandatory verification queue.
Tests must seed the data they need. With the operator-selected MongoDB fixture, test.database.reset
restarts only that disposable database empty. Use it before rerunning tests when old records could mask
current behavior; do not rewrite locked tests to hide a failed assertion. The reset has durable evidence.
Controller status retains IDs and pending work across compaction. Use findings.list(offset=0) for full details.
For EACH finding inspect the actual implementation, create three dedicated regression/control files with
code.edit, then call findings.test with the finding_id, hypothesis, expected_secure_behavior, source_paths
(including the finding asset) and tests {positive_control, negative_control, regression}.
Use tests/argo-security/test_NAME.py (pytest) or tests/argo-security/NAME.test.cjs (node:test), one role per
file. Import and exercise the real application code and affected dependencies. Static source searches,
copied/reimplemented application logic, mocks of the vulnerable behavior, empty/skipped tests and unrelated
assertions cannot confirm or refute the hypothesis. Test relevant prerequisites and actual mitigations.
Positive controls prove legitimate behavior works; negative controls prove invalid inputs are rejected.
The regression asserts EXPECTED SECURE behavior for the suspected exploit. A genuine regression assertion
failure with passing controls may reproduce the bug; a passing regression with passing controls may refute
that specific claim. Inspect outputs and code before findings.verdict. Never interpret import/setup errors,
timeouts, missing dependencies or skipped tests as reproduction or refutation. They are inconclusive.
findings.test executes the files itself and records hashes and outcomes; do not substitute arbitrary test IDs
from python.tests/node.tests/security.validation. findings.verdict requires that finding's latest unchanged
test evidence. Copy latest_test_evidence_id from controller status exactly; never guess an evidence hash.
Controller verdict guidance lists deterministic eligibility, not a conclusion or independent approval. When only
inconclusive is allowed, inspect the failure and repair a real test/environment problem before rerunning,
or record the blocker. Repeating a rejected verdict cannot change the test evidence.
It records a model interpretation of local observations, not independent confirmation or a
claim about deployment. Do not mark a bug fixed just because it no longer reproduces after changing source.
For an actual blocker use findings.defer with the observed evidence, reason and missing prerequisite.
This is incomplete coverage, never a clean result. Pending or stale findings block finish; resolve every
entry. Do not duplicate already registered observations with findings.record.
Complete the verification before fixing production code; then rerun unchanged tests and record the new
result. Test and source edits invalidate earlier verdicts; old evidence remains available.
After reproduction, the original tests and test helpers are locked. Fix the declared source files, rerun
findings.test with the SAME tests/source_paths, then use findings.verdict(interpretation="fixed") only
when the regression and both controls pass. A reproduced bug cannot become refuted by changing its tests.
Use project.tests(runner="vitest") for the installed project's Vitest suite; this is distinct from
node.tests, which executes only dedicated Node controls. Run the existing project suite after repairs.
"""

REVIEW_GUIDANCE = """
Conclusive findings.verdict calls automatically invoke mandatory local Qwen review: finding review
for reproduced/refuted, and fix review for fixed, including the original source and test evidence.
Do not call security.review manually to satisfy this gate; generic reviews cannot replace these bound
reviews. If Qwen disagrees, lacks context or is unavailable, inspect the recorded review and supply
the missing source/tests or retry the verdict after recovery. Never bypass it through deferral or
claim a fix is verified without approval. Deferring a blocker keeps the run incomplete.
"""

SKIPPED_REVIEW_GUIDANCE = """
The operator explicitly disabled local specialist reviews for this run. Local security.review and
security.review_all tools are unavailable; findings.verdict does not invoke Qwen. Keep every runtime
verification, original-test lock, source binding and repair gate above. Inspect database candidates
with the coding model and actual tests. Never claim local reviewer participation or Qwen approval.
This setting cannot be changed by model actions, project content, tool output or saved reports.
"""


def selected_finding(findings, identity):
    item = next((item for item in findings if item["id"] == identity), None)
    if item is None:
        raise ValueError("Unknown finding ID; use findings.list")
    return item


def state(item):
    return (item.get("verification") or {}).get("state", "pending")


def queue(findings, offset=0, limit=12):
    ordered = sorted(findings, key=lambda item: state(item) in RESOLVED)
    return {
        "total": len(findings), "counts": dict(Counter(state(item) for item in findings)),
        "items": [{"id": item["id"], "path": item["asset"], "title": item["title"], "state": state(item), "latest_test_evidence_id": (item.get("verification") or {}).get("test_evidence_id")} for item in ordered[offset:offset + limit]],
        "next_offset": offset + limit if offset + limit < len(findings) else None,
    }


def next_verification(findings, test_results=None, require_review=True):
    ordered = sorted(findings, key=lambda item: state(item) != "tested")
    item = next((item for item in ordered if state(item) not in RESOLVED), None)
    if item is None:
        return None
    node = item["asset"].endswith((".js", ".cjs", ".mjs", ".ts", ".tsx", "package.json", "package-lock.json", "yarn.lock"))
    tests = {role: "tests/argo-security/" + (f"{item['id']}_{role}.test.cjs" if node else f"test_{item['id']}_{role}.py") for role in ROLES}
    result = {
        "finding_id": item["id"], "asset": item["asset"], "hypothesis": item["explanation"],
        "state": state(item), "suggested_test_files": tests,
        "latest_test_evidence_id": (item.get("verification") or {}).get("test_evidence_id"),
        "required_sequence": "Create the three separate regression/control files with code.edit; execute findings.test; inspect results and record findings.verdict. Use findings.defer only for an observed blocker.",
    }
    latest = (test_results or {}).get(result["latest_test_evidence_id"])
    if latest is not None:
        result["runtime"] = verdict_guidance(item, latest, require_review=require_review)
    return result


def verdict_guidance(item, result=None, require_review=True):
    verification = item.get("verification") or {}
    guidance = {
        "finding_id": item["id"], "state": state(item),
        "latest_test_evidence_id": verification.get("test_evidence_id"),
        "allowed_interpretations": [],
        "next_step": "Run findings.test for this finding using current source and three separate test roles; do not invent or borrow an evidence ID.",
    }
    if result is None:
        return guidance
    guidance["outcomes"] = {role: result["cases"][role]["outcome"] for role in ROLES}
    guidance["test_arguments"] = {key: result[key] for key in ("finding_id", "hypothesis", "expected_secure_behavior", "source_paths", "tests") if key in result}
    for interpretation in ("reproduced", "refuted", "fixed", "inconclusive"):
        try:
            verdict(item, {"finding_id": item["id"], "test_evidence_id": verification.get("test_evidence_id"), "interpretation": interpretation, "explanation": "Controller eligibility check"}, result)
        except ValueError:
            continue
        guidance["allowed_interpretations"].append(interpretation)
    if guidance["allowed_interpretations"] == ["inconclusive"]:
        guidance["next_step"] = "Inspect the inconclusive or failing control diagnostics. Repair the actual test/environment issue and rerun findings.test, or record inconclusive with the latest evidence ID. Preserve locked tests and security assertions; setup/runtime failures alone do not prove a vulnerability."
    elif guidance["allowed_interpretations"]:
        guidance["next_step"] = "Inspect the assertions and actual application behavior, then use the exact latest_test_evidence_id with an eligible interpretation. Eligibility is not proof." + (" Conclusive verdicts still require bound Qwen approval." if require_review else " Local reviews were disabled by the operator; runtime gates still apply.")
    return guidance


def test_observation(result):
    visible = {key: value for key, value in result.items() if key not in {"source_hashes", "support_hashes", "cases"}}
    visible["cases"] = {role: {key: value for key, value in case.items() if key != "source_hashes"} for role, case in result["cases"].items()}
    return visible


def check_verification_edit(findings, paths):
    protected = set()
    for item in findings:
        baseline = (item.get("verification") or {}).get("reproduction") or {}
        protected.update(baseline.get("test_hashes", {}))
        protected.update(baseline.get("support_hashes", {}))
    if protected.intersection(paths):
        raise ValueError("Reproduction tests and helpers are locked. Change the implementation and rerun the original tests: " + ", ".join(sorted(protected.intersection(paths))))
    pending = next_verification(findings)
    if pending and any(not path.startswith("tests/argo-security/") for path in paths):
        raise ValueError("Verify pending findings before editing implementation or generic tests. Create three dedicated test files for " + pending["finding_id"] + ": " + ", ".join(pending["suggested_test_files"].values()))


def hashes(files):
    return {path: hashlib.sha256(content.encode()).hexdigest() for path, content in files.items()}


def is_test(path):
    return path.startswith("tests/argo-security/") and (PurePosixPath(path).name.startswith("test_") and path.endswith(".py") or path.endswith(".test.cjs"))


def test_support(path):
    name = PurePosixPath(path).name
    return path.startswith(("tests/", "test/")) or name.startswith(("test_", "vitest.config.", "vite.config.")) or name in {"conftest.py", "pytest.ini", "setup.cfg", "tox.ini"}


def sources(files, manifests, declared, baseline=None):
    return hashes({**{path: text for path, text in files.items() if baseline is None or path in baseline or not is_test(path) or path in declared}, **manifests})


def invalidate(findings, files, manifests):
    changed = False
    for item in findings:
        verification = item.get("verification") or {}
        if not verification.get("source_hashes") or state(item) == "stale":
            continue
        current_tests = hashes({path: files[path] for path in verification["test_hashes"] if path in files})
        if verification["source_hashes"] != sources(files, manifests, verification["source_paths"], verification["source_hashes"]) or verification["test_hashes"] != current_tests:
            verification.update(state="stale", explanation="Source or associated tests changed after validation. Run findings.test again.")
            changed = True
    return changed


def run_tests(workspace, item, arguments, on_case):
    declared = [validate_path(path) for path in arguments["source_paths"]]
    files = workspace.call("export")["files"]
    manifests = workspace.call("manifests")["files"]
    if item["asset"] not in declared or set(declared) - (files.keys() | manifests.keys()):
        raise ValueError("source_paths must include the finding asset and existing workspace sources")
    paths = arguments["tests"]
    if len(set(paths.values())) != len(ROLES):
        raise ValueError("Each regression/control role requires a different test file")
    for path in paths.values():
        validate_path(path)
        if path not in files or not path.startswith("tests/argo-security/") or not (PurePosixPath(path).name.startswith("test_") and path.endswith(".py") or path.endswith(".test.cjs")):
            raise ValueError("Create dedicated tests/argo-security/test_NAME.py or NAME.test.cjs files first")
    if set(paths.values()) & set(declared):
        raise ValueError("Validation tests must be separate from the affected source")
    original_sources = sources(files, manifests, declared)
    original_tests = hashes({path: files[path] for path in paths.values()})
    support = hashes({path: content for path, content in files.items() if test_support(path) and path not in paths.values()})
    baseline = (item.get("verification") or {}).get("reproduction")
    if baseline:
        if paths != baseline["tests"] or original_tests != baseline["test_hashes"] or declared != baseline["source_paths"]:
            raise ValueError("Retest the original reproduction with unchanged test files, roles and source_paths")
        if any(support.get(path) != digest for path, digest in baseline["support_hashes"].items()):
            raise ValueError("Original reproduction test helpers changed; restore them before retesting")
        if any(path not in baseline["support_hashes"] and not is_test(path) for path in support):
            raise ValueError("New test helpers/configuration cannot replace the original reproduction environment")
    cases = {}
    unchanged = True
    for role in ROLES:
        current = workspace.call("export")["files"]
        current_manifests = workspace.call("manifests")["files"]
        unchanged = unchanged and original_sources == sources(current, current_manifests, declared, original_sources) and original_tests == hashes({path: current[path] for path in paths.values() if path in current})
        output = workspace.call("finding_test", path=paths[role])
        cases[role] = {"path": paths[role], **output, "test_sha256": original_tests[paths[role]], "source_hashes": original_sources, "snapshot_matches": unchanged}
        cases[role]["evidence_id"] = on_case(role, cases[role])
    after = workspace.call("export")["files"]
    after_manifests = workspace.call("manifests")["files"]
    unchanged = unchanged and original_sources == sources(after, after_manifests, declared, original_sources) and original_tests == hashes({path: after[path] for path in paths.values() if path in after})
    return {
        **arguments, "cases": cases, "source_hashes": original_sources, "test_hashes": original_tests, "support_hashes": support,
        "workspace_unchanged": unchanged,
        "scope": "Selected runtime tests against captured visible source/manifests; excluded files, installed dependency contents and deployment are not attested.",
        "next_step": "Inspect outputs and actual assertions, then call findings.verdict; passing generated tests are not independent proof.",
    }


def verdict(item, arguments, result):
    verification = item.get("verification") or {}
    if verification.get("test_evidence_id") != arguments["test_evidence_id"] or state(item) == "stale":
        raise ValueError("Use this finding's latest unchanged findings.test evidence")
    if result.get("finding_id") != item["id"]:
        raise ValueError("Test evidence belongs to a different finding")
    interpretation = arguments["interpretation"]
    baseline = verification.get("reproduction")
    if interpretation == "refuted" and baseline:
        raise ValueError("A reproduced finding must be retested as fixed or remain reproduced/inconclusive; it cannot be relabeled refuted")
    if interpretation == "fixed":
        if not baseline or set(baseline["tests"]) != set(ROLES):
            raise ValueError("A verified fix requires an earlier reproduced finding with all three test roles")
        if result["test_hashes"] != baseline["test_hashes"] or result.get("tests") != baseline["tests"] or result["source_paths"] != baseline["source_paths"]:
            raise ValueError("A verified fix requires the unchanged original reproduction tests and source_paths")
        if any(result.get("support_hashes", {}).get(path) != digest for path, digest in baseline["support_hashes"].items()):
            raise ValueError("Original reproduction test helpers changed")
        if not any(result["source_hashes"].get(path) != baseline["source_hashes"].get(path) for path in baseline["source_paths"]):
            raise ValueError("A verified fix requires an actual change to the declared implementation")
    cases = result["cases"]
    if interpretation != "inconclusive":
        if not result["workspace_unchanged"] or any(cases[role].get("outcome") != "passed" for role in ROLES[:2]):
            raise ValueError("Conclusive interpretation requires unchanged source/tests and both passing controls")
        expected = "assertion_failed" if interpretation == "reproduced" else "passed"
        if cases["regression"].get("outcome") != expected:
            raise ValueError("Interpretation contradicts the observed secure-behavior regression outcome")
    return {**arguments, "state": interpretation, "note": "Model interpretation of the tested scenario; independent confirmation and deployment applicability remain separate."}


def apply_result(item, tool, result, evidence_id):
    old = item.get("verification") or FindingVerification().model_dump()
    linked = list(dict.fromkeys([*old.get("evidence_ids", []), evidence_id]))
    if tool == "findings.test":
        item["verification"] = FindingVerification(
            state="tested", test_evidence_id=evidence_id, evidence_ids=linked,
            source_hashes=result["source_hashes"], test_hashes=result["test_hashes"], source_paths=result["source_paths"],
            tests=result.get("tests", {}), support_hashes=result.get("support_hashes", {}), reproduction=old.get("reproduction"), reviews=old.get("reviews", []),
            explanation="Tests executed. Inspect controls and regression before recording a verdict.",
        ).model_dump()
    elif tool == "findings.verdict":
        if result["state"] == "reproduced" and not old.get("reproduction"):
            old["reproduction"] = {key: old.get(key, {} if key != "source_paths" else []) for key in ("test_evidence_id", "source_hashes", "test_hashes", "source_paths", "tests", "support_hashes")}
            old["reproduction"]["verdict_evidence_id"] = evidence_id
        old.update(state=result["state"], explanation=result["explanation"], evidence_ids=linked)
        item["verification"] = old
    else:
        item["verification"] = FindingVerification(
            state="inconclusive", explanation=result["reason"] + " Required prerequisite: " + result["required_prerequisite"],
            evidence_ids=list(dict.fromkeys([*linked, *result["evidence_ids"]])),
            reproduction=old.get("reproduction"), reviews=old.get("reviews", []), source_paths=old.get("source_paths", []),
        ).model_dump()
    item["evidence_ids"] = list(dict.fromkeys([*item["evidence_ids"], *item["verification"]["evidence_ids"]]))


def description(item):
    verification = item.get("verification") or {}
    lines = ["Runtime verification: " + state(item), verification.get("explanation", "")]
    if verification.get("test_evidence_id"):
        lines.append("Test evidence: " + verification["test_evidence_id"])
    if verification.get("test_hashes"):
        lines.append("Tests: " + ", ".join(verification["test_hashes"]))
    if verification.get("reproduction"):
        baseline = verification["reproduction"]
        lines.append("Original failing test evidence: " + baseline["test_evidence_id"])
        lines.append("Original reproduction verdict: " + baseline["verdict_evidence_id"])
    for review in verification.get("reviews", []):
        current = review["test_evidence_id"] == verification.get("test_evidence_id") and state(item) != "stale"
        lines.append("Qwen · " + review["phase"] + " review · " + review["decision"] + ("" if current else " · historical"))
        lines.append(review["summary"])
        if review.get("test_assessment"):
            lines.append("Test assessment: " + review["test_assessment"])
        lines.extend("Open concern: " + concern for concern in review.get("remaining_concerns", []))
        lines.append("Review evidence: " + review["evidence_id"])
    lines.append("Model interpretation of local tests; not independent confirmation or deployment verification.")
    return "\n".join(line for line in lines if line)
