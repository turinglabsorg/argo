import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url, model, path):
    size = model["size"]
    part_size = 128 * 1024**2
    segments = [
        (index, start, min(size - 1, start + part_size - 1))
        for index, start in enumerate(range(0, size, part_size))
    ]

    def fetch(segment):
        index, start, end = segment
        part = path.with_suffix(f".part-{index}")
        if part.exists() and part.stat().st_size == end - start + 1:
            return part
        for attempt in range(6):
            offset = part.stat().st_size if part.exists() else 0
            if offset > end - start + 1:
                part.unlink()
                offset = 0
            if offset == end - start + 1:
                return part
            request = urllib.request.Request(url, headers={"Range": f"bytes={start + offset}-{end}"})
            try:
                with urllib.request.urlopen(request, timeout=90) as response, part.open("ab") as stream:
                    if (
                        response.status != 206
                        or response.headers.get("Content-Range") != f"bytes {start + offset}-{end}/{size}"
                    ):
                        raise RuntimeError("Server returned an unexpected download range")
                    remaining = end - start + 1 - offset
                    while remaining:
                        block = response.read(min(1024**2, remaining))
                        if not block:
                            raise OSError("Incomplete model segment")
                        stream.write(block)
                        remaining -= len(block)
                return part
            except (OSError, urllib.error.URLError):
                if attempt == 5:
                    raise
                time.sleep(min(2**attempt, 15))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(fetch, segment) for segment in segments]
        for index, future in enumerate(as_completed(futures), 1):
            future.result()
            if index % 4 == 0 or index == len(segments):
                print(f"{model['alias']}: {index}/{len(segments)} segments", flush=True)
    temporary = path.with_suffix(".partial")
    with temporary.open("wb") as output:
        for index, _, _ in segments:
            with path.with_suffix(f".part-{index}").open("rb") as source:
                shutil.copyfileobj(source, output, 8 * 1024**2)
    if sha256(temporary) != model["sha256"]:
        raise RuntimeError("Model checksum mismatch")
    os.replace(temporary, path)
    for index, _, _ in segments:
        path.with_suffix(f".part-{index}").unlink()


def main():
    root = Path(__file__).resolve().parents[1]
    registry = json.loads((root / "config/models.lock.json").read_text())
    destination = Path.home() / ".argo" / "models"
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    for model in registry["models"]:
        path = destination / model["filename"]
        if not path.is_file() or sha256(path) != model["sha256"]:
            if shutil.disk_usage(destination).free < model["size"] * 2 + 5 * 1024**3:
                raise RuntimeError("Insufficient disk space for model download and Ollama import")
            url = f"https://huggingface.co/{model['repository']}/resolve/{model['revision']}/{model['filename']}"
            print(f"Downloading pinned {model['alias']}", flush=True)
            download(url, model, path)
        print(f"Verified SHA-256: {model['alias']}", flush=True)
        modelfile = destination / (model["alias"].replace(":", "-") + ".Modelfile")
        modelfile.write_text(f"FROM {path}\nPARAMETER num_ctx 8192\nPARAMETER temperature 0\n")
        result = subprocess.run(
            ["ollama", "create", model["alias"], "-f", str(modelfile)], capture_output=True, timeout=300
        )
        if result.returncode:
            raise RuntimeError(
                "Ollama model import failed: " + result.stderr.decode(errors="replace")[-1500:]
            )
        print(f"Installed {model['alias']}", flush=True)


if __name__ == "__main__":
    main()
