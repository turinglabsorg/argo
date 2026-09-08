import bisect
import json
import os
import selectors
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from argo.scanners import finding

DATA = Path(__file__).parent / "data"


class AdapterTimeoutError(TimeoutError):
    pass


def command(arguments, timeout, check, stdin=None):
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    chunks, total = {process.stdout: [], process.stderr: []}, 0

    def feed():
        try:
            process.stdin.write(stdin)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    writer = threading.Thread(target=feed, daemon=True) if stdin is not None else None
    if writer:
        writer.start()
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            check()
            if time.monotonic() > deadline:
                raise AdapterTimeoutError("Adapter deadline exceeded")
            for key, _ in selector.select(0.1):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                total += len(block)
                if total > 8 * 1024 * 1024:
                    raise ValueError("Adapter output limit exceeded")
                chunks[key.fileobj].append(block)
        process.wait(timeout=2)
        return process.returncode, b"".join(chunks[process.stdout]), b"".join(chunks[process.stderr])
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if writer:
            writer.join(timeout=1)


def scan_snapshot(snapshot, store, check, timeout, originals):
    lock = json.loads((DATA / "scanners.lock.json").read_text())
    findings, gaps = [], []
    for tool in ("semgrep", "gitleaks"):
        check()
        image = lock[tool]
        if "@sha256:" not in image:
            raise ValueError("Scanner image must be digest-pinned")
        container = "argo-" + uuid.uuid4().hex
        output_directory = tempfile.TemporaryDirectory(prefix="argo-scanner-output-")
        report_path = Path(output_directory.name) / "report.json"
        arguments = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            container,
            "--network",
            "none",
            "--user",
            f"{os.getuid() or 65534}:{os.getgid() or 65534}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "2g",
            "--cpus",
            "2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "-e",
            "HOME=/tmp",
        ]
        input_bytes, offsets, assets = None, [], []
        if tool == "semgrep":
            arguments += [
                "-v",
                f"{snapshot}:/src:ro",
                "-v",
                f"{DATA / 'rules'}:/rules:ro",
                "--entrypoint",
                "timeout",
                image,
                str(timeout),
                "semgrep",
                "scan",
                "--config",
                "/rules/core.yml",
                "--json",
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-git-ignore",
                "--jobs",
                "2",
                "/src",
            ]
        else:
            arguments += [
                "-i",
                "-v",
                f"{output_directory.name}:/out",
                "--entrypoint",
                "timeout",
                image,
                str(timeout),
                "gitleaks",
                "stdin",
                "--redact=100",
                "--report-format",
                "json",
                "--report-path",
                "/out/report.json",
                "--no-banner",
                "--exit-code",
                "0",
            ]
            count, texts = 1, []
            for asset, source in originals:
                offsets.append(count)
                assets.append(asset)
                texts.append(source.rstrip("\n") + "\n")
                count += texts[-1].count("\n")
            input_bytes = "".join(texts).encode()
        try:
            code, output, _ = command(arguments, timeout, check, input_bytes)
            if code:
                gaps.append(f"{tool}: isolated scanner failed (exit {code})")
                continue
            if tool == "gitleaks":
                descriptor = os.open(report_path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as stream:
                    output = stream.read(8 * 1024 * 1024 + 1)
                if len(output) > 8 * 1024 * 1024:
                    raise ValueError("Oversized scanner report")
            data = json.loads(output)
            records = data.get("results", []) if tool == "semgrep" else data
            if tool == "semgrep" and data.get("errors"):
                gaps.append("Semgrep reported incomplete file coverage")
            evidence_id = store.add("scanner_result", {"tool": tool, "image": image, "result": data})
            for item in records:
                if tool == "semgrep":
                    asset = item["path"].removeprefix("/src/")
                    line, rule = item["start"]["line"], item["check_id"]
                    title, cwe = item["extra"]["message"], item["extra"].get("metadata", {}).get("cwe")
                else:
                    position = max(0, bisect.bisect_right(offsets, item["StartLine"]) - 1)
                    asset = assets[position] if assets else "stdin"
                    line = item["StartLine"] - (offsets[position] if offsets else 1) + 1
                    rule, title, cwe = "gitleaks." + item["RuleID"], "Potential exposed credential", "CWE-798"
                record = finding(
                    asset,
                    line,
                    rule,
                    title,
                    cwe,
                    "An isolated scanner reported this pattern. Exploitability or credential validity has not been tested.",
                    "Review the cited rule and evidence, correct the issue, and rerun the check.",
                )
                record.evidence_ids = [evidence_id]
                findings.append(record)
        except (TimeoutError, ValueError, OSError, KeyError, TypeError):
            gaps.append(f"{tool}: scanner unavailable, timed out, or returned invalid output")
        finally:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            finally:
                output_directory.cleanup()
    return findings, gaps
