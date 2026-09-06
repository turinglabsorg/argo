import json
import re
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from argo.sandbox import command

WORKER_CONFIG = Path.home() / ".argo" / "worker.json"
MAX_TOTAL = 2 * 1024 * 1024


def validate_path(name):
    if not isinstance(name, str):
        raise ValueError("Workspace path must be a string")
    path = PurePosixPath(name)
    if (
        not name or not path.parts or len(name) > 240 or path.is_absolute() or str(path) != name
        or any(p.startswith(".") for p in path.parts)
        or any(ord(c) < 32 or ord(c) > 126 for c in name) or "\\" in name
    ):
        raise ValueError("Expected a visible relative workspace path")
    return name


def validate_files(files):
    if not isinstance(files, dict) or len(files) > 100:
        raise ValueError("Workspace file count exceeded")
    for name, content in files.items():
        validate_path(name)
        if not isinstance(content, str) or len(content.encode()) > 96 * 1024:
            raise ValueError("Workspace file size exceeded")
    if sum(len(content.encode()) for content in files.values()) > MAX_TOTAL:
        raise ValueError("Workspace size exceeded")
    if len(json.dumps(files).encode()) > 6 * 1024**2:
        raise ValueError("Serialized workspace size exceeded")
    return files


def worker_image():
    if WORKER_CONFIG.is_symlink() or not WORKER_CONFIG.is_file():
        raise RuntimeError("Install the isolated worker with: uv run python scripts/install_worker.py")
    value = json.loads(WORKER_CONFIG.read_text())["image"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise ValueError("Worker must be pinned to a local image digest")
    return value


def options(name, image, network="none"):
    return [
        "docker", "run", "--pull", "never", "--name", name, "--network", network,
        "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "768m",
        "--memory-swap", "768m", "--cpus", "2", "--ipc", "none",
        "--tmpfs", "/workspace:rw,nosuid,nodev,size=256m,uid=65532,gid=65532,mode=700",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700",
        "--label", "dev.argo.worker=true", "--init", "-i", image,
    ]


def remove(name):
    result = subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10)
    if result.returncode and b"No such container" not in result.stderr:
        raise RuntimeError("Could not remove isolated worker " + name)


def decode(code, output):
    if code:
        raise RuntimeError("Isolated worker process failed with exit " + str(code))
    data = json.loads(output)
    if not data.get("ok"):
        if data.get("fatal"):
            raise TimeoutError(data.get("error", "Worker stopped"))
        raise ValueError(data.get("error", "Invalid worker response"))
    return data["result"]


class Workspace:
    def __init__(self, check=lambda: None, image=None):
        self.check = check
        self.image = image or worker_image()
        self.name = "argo-code-" + uuid.uuid4().hex
        self.active = False

    def __enter__(self):
        try:
            args = options(self.name, self.image)
            args.insert(2, "-d")
            code, _, _ = command([*args, "idle"], 30, self.check)
            if code:
                raise RuntimeError("Cannot start the isolated workspace")
            self.active = True
            details = self.inspect()
            if details["Mounts"] or details["HostConfig"]["NetworkMode"] != "none":
                raise RuntimeError("Workspace isolation validation failed")
            return self
        except BaseException:
            remove(self.name)
            raise

    def inspect(self):
        code, output, _ = command(["docker", "inspect", self.name], 10, self.check)
        if code:
            raise RuntimeError("Cannot inspect worker")
        return json.loads(output)[0]

    def call(self, action, **arguments):
        if not self.active:
            raise RuntimeError("Workspace is closed")
        if action == "write":
            validate_files(arguments.get("files"))
        if "path" in arguments:
            validate_path(arguments["path"])
        try:
            code, output, _ = command(
                ["docker", "exec", "-i", self.name, "python", "-I", "/opt/argo/worker.py"],
                60, self.check, json.dumps({"action": action, **arguments}).encode(),
            )
        except BaseException:
            self.close()
            raise
        try:
            result = decode(code, output)
        except TimeoutError:
            self.close()
            raise
        if action == "export":
            validate_files(result["files"])
        return result

    def close(self):
        if self.active:
            remove(self.name)
            self.active = False

    def __exit__(self, *_):
        self.close()


def remote_call(endpoint, tool=None, arguments=None, check=lambda: None):
    name = "argo-mcp-" + uuid.uuid4().hex
    args = options(name, worker_image(), "bridge")
    position = args.index("-i")
    args[position:position] = ["--entrypoint", "python"]
    try:
        code, output, _ = command(
            [*args, "-I", "/opt/argo/remote.py"], 60, check,
            json.dumps({"endpoint": endpoint, "tool": tool, "arguments": arguments}).encode(),
        )
        return decode(code, output)
    finally:
        remove(name)
