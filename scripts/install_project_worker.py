"""Build a worker image carrying one project's declared Python dependencies.

The audited project's own tests cannot import its application code in the stock worker, which
carries only pytest and bandit, so every finding about that code can only end inconclusive. This
build installs the project's declared requirements once, with the network; the agent run itself
stays offline and unprivileged as before.

The packages come from the audited project, so read its requirements file before building: this
step installs and executes third-party package code on this computer.
"""

import argparse
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from argo.evidence import private_dir
from argo.workspace import PROJECT_WORKERS, project_directory, requirements_digest, worker_image


def base_tag(base):
    """BuildKit resolves FROM as a repository, so the pinned base needs a name that is only ever it."""
    tag = "argo-worker-base:" + base.removeprefix("sha256:")[:32]
    subprocess.run(["docker", "tag", base, tag], check=True)
    resolved = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if resolved != base:
        raise RuntimeError("The base worker tag does not resolve to the pinned image")
    return tag


def build(project, requirements):
    base = worker_image()
    source = project / requirements
    digest = requirements_digest(source)
    root = Path(__file__).resolve().parents[1]
    tag = base_tag(base)
    try:
        with tempfile.TemporaryDirectory(prefix="argo-project-worker-") as context:
            (Path(context) / "requirements.txt").write_bytes(source.read_bytes())
            identity = Path(context) / "image.id"
            subprocess.run(
                ["docker", "build", "--iidfile", str(identity), "--build-arg", "BASE=" + tag,
                 "-f", str(root / "worker/project.Dockerfile"), context],
                check=True,
            )
            image = identity.read_text().strip()
    finally:
        subprocess.run(["docker", "rmi", "--no-prune", tag], capture_output=True)
    return {
        "image": image, "base": base, "requirements": requirements,
        "requirements_sha256": digest, "built_at": datetime.now(timezone.utc).isoformat(),
    }


def record(project, entry):
    private_dir(PROJECT_WORKERS.parent)
    document = json.loads(PROJECT_WORKERS.read_text()) if PROJECT_WORKERS.is_file() else {"projects": {}}
    document.setdefault("projects", {})[str(project)] = entry
    PROJECT_WORKERS.write_text(json.dumps(document, indent=2) + "\n")
    PROJECT_WORKERS.chmod(0o600)


def imports(project, image, module):
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python",
         "--mount", f"type=bind,src={project},dst=/workspace,readonly", "-w", "/workspace",
         image, "-c", "import " + module],
        capture_output=True, text=True, timeout=300,
    )
    return {"module": module, "imported": result.returncode == 0, "error": result.stderr.strip().splitlines()[-1:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--check-import", default=None, help="Report whether this module imports in the built image")
    arguments = parser.parse_args()
    project = project_directory(arguments.project)
    entry = build(project, arguments.requirements)
    record(project, entry)
    report = {"project": str(project), "config": str(PROJECT_WORKERS), **entry}
    if arguments.check_import:
        report["import_check"] = imports(project, entry["image"], arguments.check_import)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
