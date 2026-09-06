import ast
import hashlib
import json
import os
import re
import stat
import tomllib
from pathlib import Path

from argo.contracts import Finding, Package
from argo.evidence import ASSIGNMENT, PRIVATE_KEY, TOKEN, URL_CREDENTIAL, URL_SECRET, redact

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".argo",
    ".ssh",
    ".aws",
    ".gcloud",
    ".hush",
}
SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".txt",
    ".md",
    ".html",
    ".sh",
    ".lock",
}
VERSION = re.compile(r"^\d+(?:\.\d+)+(?:[-+._a-zA-Z0-9]*)$")


def finding(asset, line, rule, title, cwe, explanation, remediation, severity="high"):
    identity = hashlib.sha256(f"{asset}:{line}:{rule}".encode()).hexdigest()[:16]
    return Finding(
        id=identity,
        asset=asset,
        line=line,
        rule=rule,
        title=title,
        severity=severity,
        cwe=cwe,
        explanation=explanation,
        remediation=remediation,
    )


def read_sources(root: Path, output_root: Path, check):
    count, total = 0, 0
    for directory, dirs, files, directory_fd in os.fwalk(root, follow_symlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in EXCLUDED
            and not (Path(directory) / d).is_symlink()
            and not (Path(directory) / d).resolve().is_relative_to(output_root)
        )
        for name in sorted(files):
            check()
            path = Path(directory) / name
            if (
                name.startswith(".env")
                or name in {".npmrc", ".pypirc", "credentials.json"}
                or path.suffix not in SUFFIXES
            ):
                continue
            relative = str(path.relative_to(root))
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(descriptor, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024 or info.st_nlink > 1:
                        yield relative, None, "Skipped oversized, linked or nonregular file"
                        continue
                    data = stream.read(1024 * 1024 + 1)
            except OSError:
                yield relative, None, "Skipped inaccessible file or symlink"
                continue
            count += 1
            total += len(data)
            if count > 5000 or total > 128 * 1024 * 1024:
                raise ValueError("Repository inventory budget exceeded")
            if b"\0" in data or len(data) > 1024 * 1024:
                yield relative, None, "Skipped binary or oversized file"
                continue
            yield relative, data.decode("utf-8", errors="replace"), None


def scan_source(asset: str, source: str) -> tuple[list[Finding], str, list[str]]:
    results, gaps = [], []
    secret_lines = set()
    for pattern in (ASSIGNMENT, TOKEN, PRIVATE_KEY, URL_CREDENTIAL, URL_SECRET):
        for match in pattern.finditer(source):
            line = source[: match.start()].count("\n") + 1
            if line not in secret_lines:
                results.append(
                    finding(
                        asset,
                        line,
                        "argo.secret-literal",
                        "Potential embedded credential",
                        "CWE-798",
                        "A credential-like literal was detected. Its value is withheld; validity has not been tested.",
                        "Remove the literal, use a secret reference, and review whether rotation is required.",
                    )
                )
                secret_lines.add(line)
    sanitized = redact(source)
    if asset.endswith(".py"):
        try:
            tree = ast.parse(sanitized)
        except (SyntaxError, ValueError, RecursionError):
            return results, sanitized, ["Python syntax could not be parsed"]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            if name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
                results.append(
                    finding(
                        asset,
                        node.lineno,
                        "argo.python.dynamic-eval",
                        "Dynamic code evaluation",
                        "CWE-95",
                        "A nonliteral value reaches eval/exec. Determine whether untrusted input can reach this call.",
                        "Replace code evaluation with a parser or explicit operation mapping.",
                    )
                )
            if name.startswith("subprocess.") and any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in node.keywords
            ):
                results.append(
                    finding(
                        asset,
                        node.lineno,
                        "argo.python.shell",
                        "Shell-enabled subprocess",
                        "CWE-78",
                        "The subprocess call enables shell interpretation. Input provenance needs validation.",
                        "Use a fixed executable and an argument list with shell disabled.",
                    )
                )
            if (
                name.endswith((".execute", ".executemany"))
                and node.args
                and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp))
            ):
                results.append(
                    finding(
                        asset,
                        node.lineno,
                        "argo.python.sql-construction",
                        "Dynamically constructed SQL",
                        "CWE-89",
                        "SQL is interpolated at the database call. This static observation does not prove input reachability.",
                        "Use parameterized queries and test malicious-looking input as data.",
                    )
                )
    if asset.endswith((".js", ".ts", ".tsx", ".jsx")):
        for number, line in enumerate(sanitized.splitlines(), 1):
            if re.search(r"\binnerHTML\s*=\s*(?![\"'`])\w", line):
                results.append(
                    finding(
                        asset,
                        number,
                        "argo.js.innerhtml",
                        "Dynamic innerHTML assignment",
                        "CWE-79",
                        "A nonliteral expression is assigned to innerHTML. Sanitization and input provenance need review.",
                        "Use textContent or a reviewed sanitizer appropriate for the HTML context.",
                        "medium",
                    )
                )
    return results, sanitized, gaps


def dependencies(asset: str, source: str) -> tuple[list[Package], list[str]]:
    results, gaps = [], []
    name = Path(asset).name
    try:
        if name == "package-lock.json":
            data = json.loads(source)
            if data.get("lockfileVersion") not in (2, 3):
                return [], ["Unsupported npm lockfile version; exact dependency coverage unavailable"]
            for key, record in data.get("packages", {}).items():
                if not key or not isinstance(record, dict) or "node_modules/" not in key:
                    continue
                package = record.get("name") or key.rsplit("node_modules/", 1)[-1]
                version = record.get("version", "")
                if VERSION.fullmatch(version):
                    results.append(Package(ecosystem="npm", name=package, version=version, asset=asset))
                else:
                    gaps.append("An npm package has a non-version resolution")
        elif name == "requirements.txt":
            for line in source.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)(?:\s*#.*)?", line)
                if match and VERSION.fullmatch(match[2]):
                    results.append(Package(ecosystem="PyPI", name=match[1], version=match[2], asset=asset))
                else:
                    gaps.append("A Python requirement is not an exact supported pin")
        elif name == "uv.lock":
            for record in tomllib.loads(source).get("package", []):
                if isinstance(record.get("source"), dict) and "registry" in record["source"]:
                    results.append(
                        Package(ecosystem="PyPI", name=record["name"], version=record["version"], asset=asset)
                    )
        elif name in {"yarn.lock", "pnpm-lock.yaml", "poetry.lock", "bun.lock"}:
            gaps.append("This lockfile format is not supported yet")
    except (ValueError, TypeError, KeyError, AttributeError):
        gaps.append("Dependency file could not be parsed")
    return results, gaps
