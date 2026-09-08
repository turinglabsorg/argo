"""Immutable workspace adapter. This file executes only inside the worker image."""

import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import PurePosixPath

import yaml

ROOT = "/workspace"
MAX_FILE = 96 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 1000 if os.environ.get("ARGO_PROJECT_MOUNT") == "1" else 100
EXCLUDED = {"__pycache__", "node_modules", "vendor", "dist", "build", "target", "venv"}
MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


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


def read_file(name, limit=MAX_FILE):
    directory, leaf = parent(name)
    try:
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError("Only bounded regular files can be read")
            data = source.read(limit + 1)
            if len(data) > limit:
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


def execute(argv, timeout=50, capture_limits=False):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        limit = None
        try:
            while process.poll() is None:
                if time.monotonic() > deadline:
                    limit = "deadline"
                elif os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 256 * 1024:
                    limit = "output"
                if limit:
                    if capture_limits:
                        break
                    raise TimeoutError("Execution deadline or output budget exceeded")
                time.sleep(0.05)
            if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 256 * 1024:
                limit = "output"
                if not capture_limits:
                    raise TimeoutError("Execution output budget exceeded")
            out.seek(0)
            err.seek(0)
            result = {"exit_code": 124 if limit else process.returncode, "stdout": out.read(128 * 1024).decode(errors="replace"), "stderr": err.read(128 * 1024).decode(errors="replace")}
            if limit:
                result.update(execution_limit=limit, timeout_seconds=timeout)
            return result
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)


def project_tests(runner):
    if runner != "vitest":
        raise ValueError("Supported project runner: vitest")
    entrypoint = "node_modules/vitest/vitest.mjs"
    read_file(entrypoint)
    before = files()
    before_manifests = manifests()
    with tempfile.TemporaryDirectory(prefix="argo-vitest-") as directory:
        report = directory + "/results.json"
        result = execute(["node", ROOT + "/" + entrypoint, "run", "--maxWorkers=1", "--no-file-parallelism", "--reporter=json", "--outputFile=" + report], timeout=300, capture_limits=True)
        result.update(runner=runner, outcome="inconclusive", scope="Installed project Vitest suite using its existing configuration")
        try:
            with open(report, "rb") as stream:
                raw = stream.read(2 * 1024**2 + 1)
            if len(raw) > 2 * 1024**2:
                raise ValueError("Project test report exceeds its budget")
            data = json.loads(raw)
            counts = {name: data[name] for name in ("numTotalTests", "numPassedTests", "numFailedTests", "numPendingTests")}
            if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counts.values()):
                raise ValueError("Invalid project test counts")
            result["counts"] = counts
            failures = []
            for suite in data.get("testResults", []):
                if not isinstance(suite, dict):
                    continue
                path = str(suite.get("name", "")).removeprefix(ROOT + "/")[:240]
                failed = [case for case in suite.get("assertionResults", []) if isinstance(case, dict) and case.get("status") == "failed"]
                for case in failed:
                    messages = case.get("failureMessages", [])
                    failures.append({"path": path, "test": str(case.get("fullName", case.get("title", "")))[:500], "message": "\n".join(str(message) for message in messages)[:4000]})
                if not failed and suite.get("status") == "failed":
                    failures.append({"path": path, "test": "suite setup or execution", "message": str(suite.get("message", ""))[:4000]})
            result.update(failures=failures[:20], failures_truncated=len(failures) > 20)
            if result["exit_code"] == 0 and data.get("success") is True and counts["numTotalTests"] > 0 and counts["numPassedTests"] == counts["numTotalTests"] and counts["numFailedTests"] == counts["numPendingTests"] == 0:
                result["outcome"] = "passed"
        except (OSError, ValueError, KeyError, TypeError):
            pass
    result["workspace_unchanged"] = files() == before and manifests() == before_manifests
    if not result["workspace_unchanged"]:
        result["outcome"] = "inconclusive"
    return result


def manifests():
    result, gaps, size = {}, [], 0
    for directory, folders, names in os.walk(ROOT, followlinks=False):
        folders[:] = sorted(p for p in folders if not p.startswith(".") and p not in EXCLUDED)
        for name in sorted(set(names) & MANIFESTS):
            path = os.path.relpath(os.path.join(directory, name), ROOT)
            try:
                content = read_file(path, 2 * 1024**2)
            except (ValueError, OSError, UnicodeError):
                gaps.append(path + ": manifest is unreadable, oversized or not a regular file")
                continue
            if len(result) >= 100 or size + len(content.encode()) > 2 * 1024**2:
                gaps.append("Manifest inventory budget exceeded")
                return {"files": result, "coverage_gaps": gaps}
            size += len(content.encode())
            result[path] = content
    return {"files": result, "coverage_gaps": gaps}


def finding_test(path):
    parts(path)
    read_file(path)
    if not path.startswith("tests/argo-security/"):
        raise ValueError("Finding tests must be inside tests/argo-security")
    outcome, counts = "inconclusive", {}
    if path.endswith(".py") and PurePosixPath(path).name.startswith("test_"):
        with tempfile.TemporaryDirectory(prefix="argo-test-") as directory:
            report = directory + "/results.json"
            result = execute([sys.executable, "-B", "/opt/argo/finding_pytest.py", ROOT + "/" + path, report], capture_limits=True)
            try:
                with open(report, "rb") as stream:
                    raw = stream.read(256 * 1024 + 1)
                if len(raw) > 256 * 1024:
                    raise ValueError("Test report exceeds its size budget")
                data = json.loads(raw)
                cases = [phase for phase in data["phases"] if phase["phase"] == "call"]
                failures = [phase for phase in cases if phase["outcome"] == "failed"]
                counts = {"tests": data["tests"], "failures": len(failures), "errors": data["collection_errors"] + sum(phase["phase"] != "call" and phase["outcome"] == "failed" for phase in data["phases"]), "skipped": sum(phase["outcome"] == "skipped" or phase["xfail"] for phase in data["phases"])}
                if cases and len(cases) == counts["tests"] and not counts["errors"] and not counts["skipped"]:
                    if result["exit_code"] == 0 and not failures:
                        outcome = "passed"
                    elif result["exit_code"] == 1 and failures and all(failure["assertion"] for failure in failures):
                        outcome = "assertion_failed"
            except (OSError, ValueError, KeyError, TypeError):
                pass
    elif path.endswith(".test.cjs"):
        result = execute(["node", "--test", "--test-reporter=tap", ROOT + "/" + path], capture_limits=True)
        counts = {name: int(value) for name, value in re.findall(r"^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$", result["stdout"], re.M)}
        explicit_tests = re.findall(r"^# Subtest: (.+)$", result["stdout"], re.M)
        explicit_tests = [name for name in explicit_tests if name != ROOT + "/" + path]
        if explicit_tests and counts.get("tests", 0) > 0 and all(counts.get(name) == 0 for name in ("cancelled", "skipped", "todo")):
            if result["exit_code"] == 0 and counts.get("fail") == 0 and counts.get("pass") == counts["tests"]:
                outcome = "passed"
            elif result["exit_code"] == 1 and counts.get("fail", 0) > 0:
                try:
                    diagnostics = [yaml.safe_load(textwrap.dedent(body)) for _, body in re.findall(r"(?m)^([ \t]+)---\n([\s\S]*?)^\1\.\.\.[ \t]*$", result["stdout"])]
                    failures = [item for item in diagnostics if isinstance(item, dict) and "failureType" in item]
                    assertions = [item for item in failures if item.get("type") == "test" and item.get("failureType") == "testCodeFailure" and item.get("code") == "ERR_ASSERTION" and item.get("name") == "AssertionError"]
                    parents = [item for item in failures if item.get("type") in {"suite", "test"} and item.get("failureType") == "subtestsFailed" and item.get("code") == "ERR_TEST_FAILURE"]
                    if assertions and len(assertions) + len(parents) == len(failures) and sum(item.get("type") == "test" for item in failures) == counts["fail"]:
                        outcome = "assertion_failed"
                except (yaml.YAMLError, TypeError, ValueError):
                    pass
    else:
        raise ValueError("Expected test_NAME.py or NAME.test.cjs")
    return {**result, "outcome": outcome, "counts": counts}


def dispatch(request):
    action = request["action"]
    if action == "list":
        return {"files": [{"path": name, "bytes": len(content.encode())} for name, content in files().items()]}
    if action == "export":
        return {"files": files()}
    if action == "read":
        return {"path": request["path"], "content": read_file(request["path"])}
    if action == "manifests":
        return manifests()
    if action == "validate_code":
        values = request["files"]
        if not isinstance(values, dict) or len(values) > 20 or sum(len(value.encode()) for value in values.values()) > MAX_TOTAL:
            raise ValueError("Code validation budget exceeded")
        with tempfile.TemporaryDirectory(prefix="argo-syntax-") as directory:
            for name, content in values.items():
                parts(name)
                if not name.endswith((".cjs", ".mjs")):
                    continue
                target = directory + "/source" + PurePosixPath(name).suffix
                with open(target, "w") as stream:
                    stream.write(content)
                if execute(["node", "--check", target])["exit_code"] != 0:
                    raise ValueError("JavaScript syntax validation failed before writing: " + name)
        return {"syntax_checked": sorted(name for name in values if name.endswith((".cjs", ".mjs")))}
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
    if action == "finding_test":
        return finding_test(request["path"])
    if action == "project_tests":
        return project_tests(request["runner"])
    if action == "node_tests":
        selected = sorted(name for name in files() if name.startswith("tests/argo-security/") and name.endswith(".test.cjs"))
        if not selected or len(selected) > 40:
            raise ValueError("Create 1–40 Node tests at tests/argo-security/NAME.test.cjs using node:test and node:assert/strict")
        return execute(["node", "--test", "--test-reporter=tap", *[ROOT + "/" + name for name in selected]])
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
