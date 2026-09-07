"""Immutable workspace adapter. This file executes only inside the worker image."""

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import PurePosixPath

ROOT = "/workspace"
MAX_FILE = 96 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 1000 if os.environ.get("ARGO_PROJECT_MOUNT") == "1" else 100
EXCLUDED = {"__pycache__", "node_modules", "vendor", "dist", "build", "target", "venv"}


def parts(name):
    path = PurePosixPath(name)
    if (
        not isinstance(name, str) or not name or not path.parts or len(name) > 240
        or path.is_absolute() or str(path) != name
        or any(p in {"", ".", ".."} or p.startswith(".") for p in path.parts)
        or any(ord(c) < 32 or ord(c) > 126 for c in name)
        or "\\" in name
    ):
        raise ValueError("Expected a visible relative workspace path")
    return path.parts


def parent(name, create=False):
    components = parts(name)
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in components[:-1]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def read_file(name):
    directory, leaf = parent(name)
    try:
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
                raise ValueError("Only bounded regular files can be read")
            data = source.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ValueError("File grew past its limit")
            return data.decode("utf-8")
    finally:
        os.close(directory)


def write_file(name, content):
    if len(content.encode()) > MAX_FILE:
        raise ValueError("File size budget exceeded")
    directory, leaf = parent(name, create=True)
    try:
        descriptor = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "w") as destination:
            info = os.fstat(destination.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Only regular files can be changed")
            destination.truncate(0)
            destination.write(content)
    finally:
        os.close(directory)


def files():
    result, size = {}, 0
    for directory, folders, names in os.walk(ROOT, followlinks=False):
        folders[:] = sorted(p for p in folders if not p.startswith(".") and p not in EXCLUDED)
        for name in sorted(names):
            if name.startswith(".") or name.endswith(".pyc"):
                continue
            path = os.path.relpath(os.path.join(directory, name), ROOT)
            try:
                content = read_file(path)
            except (ValueError, OSError, UnicodeError):
                continue
            size += len(content.encode())
            if len(result) >= MAX_FILES or size > MAX_TOTAL:
                raise ValueError("Workspace export budget exceeded")
            result[path] = content
    return result


def execute(argv):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 50
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 256 * 1024:
                    raise TimeoutError("Execution deadline or output budget exceeded")
                time.sleep(0.05)
            if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 256 * 1024:
                raise TimeoutError("Execution output budget exceeded")
            out.seek(0)
            err.seek(0)
            return {"exit_code": process.returncode, "stdout": out.read(128 * 1024).decode(errors="replace"), "stderr": err.read(128 * 1024).decode(errors="replace")}
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)


def dispatch(request):
    action = request["action"]
    if action == "list":
        return {"files": [{"path": name, "bytes": len(content.encode())} for name, content in files().items()]}
    if action == "export":
        return {"files": files()}
    if action == "read":
        return {"path": request["path"], "content": read_file(request["path"])}
    if action == "write":
        values = request["files"]
        if not isinstance(values, dict) or len(values) > 20 or sum(len(v.encode()) for v in values.values()) > MAX_TOTAL:
            raise ValueError("Write budget exceeded")
        for name in values:
            parts(name)
        for name, expected in request.get("expected", {}).items():
            try:
                actual = read_file(name)
            except FileNotFoundError:
                actual = None
            if actual != expected:
                raise ValueError("File changed while the model was working: " + name + ". Read it again before editing.")
        for name, content in values.items():
            write_file(name, content)
        return {"written": sorted(values)}
    if action == "python":
        parts(request["path"])
        read_file(request["path"])
        return execute([sys.executable, "-B", ROOT + "/" + request["path"]])
    if action == "tests":
        return execute([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    if action == "bandit":
        return execute([sys.executable, "-m", "bandit", "-r", ROOT, "-f", "json", "-x", "/workspace/tests", "-q"])
    raise ValueError("Unknown workspace action")


if __name__ == "__main__":
    if sys.argv[1:] == ["idle"]:
        while True:
            time.sleep(30)
    try:
        raw = sys.stdin.buffer.read(6 * 1024**2 + 8193)
        if len(raw) > 6 * 1024**2 + 8192:
            raise ValueError("Request too large")
        print(json.dumps({"ok": True, "result": dispatch(json.loads(raw))}))
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)[:500], "fatal": isinstance(error, TimeoutError)}))
