import json
import os
import re
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from argo.sandbox import command
from argo.test_database import MONGODB_URI, database_mode, start_mongodb

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


def validate_files(files, max_files=100):
    if not isinstance(files, dict) or len(files) > max_files:
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


def project_directory(path):
    selected = Path(path).expanduser().resolve(strict=True)
    if not selected.is_dir() or selected in {Path("/"), Path.home().resolve()}:
        raise ValueError("Choose a project directory with /workspace PATH; home and filesystem root cannot be mounted")
    if "," in str(selected) or any(ord(c) < 32 for c in str(selected)):
        raise ValueError("Docker mount paths cannot contain commas or control characters")
    return selected


def options(name, image, network="none", project=None):
    uid = f"{os.getuid() or 65532}:{os.getgid() or 65532}" if project else "65532:65532"
    workspace = ["--mount", f"type=bind,src={project},dst=/workspace", "--env", "ARGO_PROJECT_MOUNT=1"] if project else ["--tmpfs", "/workspace:rw,nosuid,nodev,size=256m,uid=65532,gid=65532,mode=700"]
    return [
        "docker", "run", "--pull", "never", "--name", name, "--network", network,
        "--read-only", "--user", uid, "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "768m",
        "--memory-swap", "768m", "--cpus", "2", "--ipc", "none",
        *workspace,
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
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
    def __init__(self, check=lambda: None, image=None, project=None, test_database="off"):
        self.check = check
        self.image = image or worker_image()
        self.name = "argo-code-" + uuid.uuid4().hex
        self.active = False
        self.project = project_directory(project) if project is not None else None
        self.test_database = database_mode(test_database)
        self.database_name = self.name + "-mongodb"
        self.database_started = False
        self.database = None
        self.database_resets = 0

    def __enter__(self):
        try:
            args = options(self.name, self.image, project=self.project)
            args.insert(2, "-d")
            code, _, _ = command([*args, "idle"], 30, self.check)
            if code:
                raise RuntimeError("Cannot start the isolated workspace")
            self.active = True
            details = self.inspect()
            mounts = details["Mounts"]
            mounted = self.project and len(mounts) == 1 and mounts[0]["Type"] == "bind" and mounts[0]["Destination"] == "/workspace" and mounts[0]["RW"] and Path(mounts[0]["Source"]).resolve() == self.project
            if (not mounted if self.project else bool(mounts)) or details["HostConfig"]["NetworkMode"] != "none":
                raise RuntimeError("Workspace isolation validation failed")
            if self.test_database == "mongodb":
                self.database_started = True
                self.database = start_mongodb(details["Id"], self.database_name, self.check)
            return self
        except BaseException:
            try:
                self.close()
            finally:
                remove(self.name)
            raise

    def inspect(self):
        code, output, _ = command(["docker", "inspect", self.name], 10, self.check)
        if code:
            raise RuntimeError("Cannot inspect worker")
        return json.loads(output)[0]

    def reset_test_database(self):
        if not self.active or not self.database_started or self.test_database != "mongodb":
            raise ValueError("Reset requires the operator-selected isolated MongoDB test fixture")
        self.check()
        remove(self.database_name)
        self.database = start_mongodb(self.inspect()["Id"], self.database_name, self.check)
        self.database_resets += 1
        return {**self.database, "reset_count": self.database_resets, "state": "empty", "scope": "Only the owned disposable test database was restarted; project files were preserved."}

    def call(self, action, **arguments):
        if not self.active:
            raise RuntimeError("Workspace is closed")
        if action == "write":
            validate_files(arguments.get("files"))
        if "path" in arguments:
            validate_path(arguments["path"])
        try:
            environment = ["--env", "ARGO_TEST_MONGODB_URI=" + MONGODB_URI] if self.database else []
            code, output, _ = command(
                ["docker", "exec", "-i", *environment, self.name, "python", "-I", "/opt/argo/worker.py"],
                330 if action == "project_tests" else 60, self.check, json.dumps({"action": action, **arguments}).encode(),
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
            validate_files(result["files"], max_files=1000 if self.project else 100)
        return result

    def close(self):
        try:
            if self.database_started:
                remove(self.database_name)
                self.database_started = False
                self.database = None
        finally:
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
