import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from argo.contracts import Actions, Engagement, Scope, utc_now
from argo.controller import run
from argo.inference import local_models
from argo.lab import create_fixture, lab_server
from argo.scope import authorize, normalize
from argo.workspace import worker_image

DEFAULT_STATE = Path.home() / ".argo" / "runs"
CYBER_MODELS = ["argo-foundation-sec:8b", "argo-vulnllm:7b"]


def run_path(root, identity):
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise ValueError("Invalid run ID")
    path = root / identity
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Run is unavailable")
    return path


def doctor():
    result = {
        "executables": {name: shutil.which(name) for name in ("python3", "docker", "ollama")},
        "ollama": {"status": "unavailable"},
        "docker": {"status": "unavailable"},
        "worker": {"status": "not installed"},
    }
    try:
        result["ollama"] = {
            "status": "ready",
            "local_models": [{"name": m["name"], "digest": m["digest"]} for m in local_models()],
        }
    except Exception:
        pass
    try:
        response = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, timeout=5
        )
        if response.returncode == 0:
            result["docker"] = {"status": "ready", "version": response.stdout.decode().strip()}
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        image = worker_image()
        response = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=5)
        result["worker"] = {"status": "ready" if response.returncode == 0 else "image unavailable", "image": image, "code_network": "none", "host_mounts": []}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        pass
    return result


def demo(state, models, scanners, **options):
    with (
        tempfile.TemporaryDirectory(prefix="argo-lab-") as temporary,
        lab_server() as vulnerable,
        lab_server(True) as fixed,
    ):
        root = Path(temporary)
        fixture = create_fixture(root / "repository")
        cache = root / "intelligence.json"
        cache.write_text(
            json.dumps(
                {
                    "packages": {
                        "npm/argo-example-package@1.0.0": {
                            "provider": "fixture",
                            "retrieved_at": utc_now(),
                            "source": "local synthetic test corpus",
                            "data": {
                                "vulns": [
                                    {
                                        "id": "ARGO-LAB-001",
                                        "summary": "Synthetic advisory for the demo only",
                                        "aliases": [],
                                    }
                                ]
                            },
                        }
                    }
                }
            )
        )
        engagement = Engagement(
            id="argo-demo",
            purpose="Operator-requested isolated synthetic demonstration",
            scope=Scope(repositories=[str(fixture)], web_origins=[vulnerable, fixed]),
            actions=Actions(local_audit=True, web_observe=True, web_validate=True),
        )
        engagement = authorize(normalize(engagement), "local-operator", "Argo demo explicitly requested")
        result = run(engagement, state, cache, models, scanners, **options)
        report = json.loads(Path(result["report"]).with_suffix(".json").read_text())
        confirmed = [item for item in report["findings"] if item["status"] == "confirmed"]
        if result["status"] == "complete" and (len(confirmed) != 1 or confirmed[0]["asset"] != vulnerable):
            raise RuntimeError("Controlled positive/negative demonstration failed")
        if result["status"] == "complete":
            result["demo_validation"] = "Vulnerable fixture confirmed; fixed control did not trigger"
        return result
