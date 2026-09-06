import json
import subprocess
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    images = json.loads((root / "src/argo/data/scanners.lock.json").read_text())
    for name, image in images.items():
        if "@sha256:" not in image:
            raise ValueError("Scanner image must be digest-pinned")
        subprocess.run(["docker", "pull", image], check=True)
        print(f"Installed pinned scanner: {name}")


if __name__ == "__main__":
    main()
