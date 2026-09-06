import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from argo.evidence import private_dir


def main():
    root = Path(__file__).resolve().parents[1]
    sources = [root / "worker/Dockerfile", root / "worker/requirements.txt", *sorted((root / "src/argo/data/agent").glob("*.py"))]
    checksum = hashlib.sha256(b"".join(p.read_bytes() for p in sources)).hexdigest()
    with tempfile.TemporaryDirectory(prefix="argo-build-") as build:
        identity = Path(build) / "image.id"
        subprocess.run(["docker", "build", "--iidfile", str(identity), "-t", "argo-worker:local", "-f", "worker/Dockerfile", "."], cwd=root, check=True)
        image = identity.read_text().strip()
    destination = Path.home() / ".argo" / "worker.json"
    private_dir(destination.parent)
    destination.write_text(json.dumps({"image": image, "source_sha256": checksum}, indent=2) + "\n")
    destination.chmod(0o600)
    print(json.dumps({"image": image, "config": str(destination)}))


if __name__ == "__main__":
    main()
