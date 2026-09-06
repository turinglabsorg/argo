import re
import uuid

from argo.network import PROBE_ORIGIN
from argo.scanners import finding


def validate_web(endpoint, broker, store):
    results = []
    response = broker.get(endpoint + "/", cors_probe=True)
    headers = response["headers"]
    if (
        headers.get("access-control-allow-origin") == PROBE_ORIGIN
        and headers.get("access-control-allow-credentials", "").lower() == "true"
    ):
        evidence = store.add(
            "cors_probe", {"origin": endpoint, "test_origin": PROBE_ORIGIN, "headers": headers}
        )
        item = finding(
            endpoint,
            None,
            "argo.web.cors-reflection",
            "Credentialed CORS reflects a test origin",
            "CWE-942",
            "The server allows the reserved test origin with credentials. Sensitive authenticated responses have not been tested; impact is unverified.",
            "Use an explicit origin allowlist and verify authenticated endpoints and browser behavior.",
            "medium",
        )
        item.evidence_ids = [evidence]
        results.append(item)
    exposed = broker.get(endpoint + "/.git/HEAD")
    if exposed["status"] == 200 and re.fullmatch(rb"ref: refs/heads/[A-Za-z0-9_./-]+\s*", exposed["body"]):
        control = broker.get(endpoint + "/argo-missing-" + uuid.uuid4().hex)
        if exposed["body_sha256"] != control["body_sha256"]:
            evidence = store.add(
                "git_metadata_exposure",
                {
                    "origin": endpoint,
                    "probe_status": exposed["status"],
                    "probe_body_sha256": exposed["body_sha256"],
                    "control_status": control["status"],
                    "control_body_sha256": control["body_sha256"],
                },
            )
            item = finding(
                endpoint + "/.git/HEAD",
                None,
                "argo.web.git-head",
                "Git HEAD metadata is publicly accessible",
                "CWE-552",
                "The server returned a valid Git HEAD reference distinct from a random missing route. No repository objects or source were downloaded.",
                "Remove the .git directory from deployment artifacts and deny access to version-control metadata.",
                "medium",
            )
            item.status = "confirmed"
            item.evidence_ids = [evidence]
            item.validation = "A bounded metadata probe matched the Git HEAD grammar; a random-route negative control returned a different body."
            results.append(item)
    return results
