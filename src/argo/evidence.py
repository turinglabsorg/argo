import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from pathlib import Path

from argo.contracts import utc_now

ASSIGNMENT = re.compile(
    r"""(?i)((?:["']?)(?:api[_-]?key|secret|password|access[_-]?token|auth[_-]?token|token)(?:["']?)\s*[:=]\s*["'])([^"'\n]{8,})(["'])"""
)
TOKEN = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9._~+/-]{8,})"
)
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----")
URL_CREDENTIAL = re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@")
URL_SECRET = re.compile(r"(?i)([?&](?:access_token|api_key|token|password|secret)=)[^&#\s]+")
SECRET_KEYS = {"password", "secret", "token", "apikey", "accesstoken", "authorization", "cookie", "setcookie"}


def redact(text: str) -> str:
    text = PRIVATE_KEY.sub("[redacted private key]", text)
    text = ASSIGNMENT.sub(lambda m: m[1] + "[redacted]" + m[3], text)
    text = URL_CREDENTIAL.sub(r"\1[redacted]@", text)
    text = URL_SECRET.sub(r"\1[redacted]", text)
    return TOKEN.sub("[redacted token]", text)


def clean(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {
            redact(str(k)): "[redacted]" if re.sub(r"[^a-z]", "", str(k).lower()) in SECRET_KEYS else clean(v)
            for k, v in value.items()
        }
    return value


def private_dir(path: Path):
    if path.is_symlink():
        raise ValueError("State directory cannot be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)


def write_private(path: Path, content: str):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


class EvidenceStore:
    def __init__(self, root: Path, engagement_id: str, scope_digest: str, limit_mib: int):
        private_dir(root)
        self.run_id = uuid.uuid4().hex
        self.path = root / self.run_id
        private_dir(self.path)
        private_dir(self.path / "evidence")
        self.limit = limit_mib * 1024 * 1024
        self.used = 0
        self.db = sqlite3.connect(self.path / "state.sqlite")
        (self.path / "state.sqlite").chmod(0o600)
        self.db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, at TEXT, kind TEXT, payload TEXT)")
        self.db.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT)")
        self.set("engagement_id", engagement_id)
        self.set("scope_sha256", scope_digest)
        self.set("run_id", self.run_id)
        self.set("created_at", utc_now())
        self.set("status", "inventory")

    def set(self, key: str, value):
        self.db.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, json.dumps(clean(value))))
        self.db.commit()

    def event(self, kind: str, value):
        self.db.execute(
            "INSERT INTO events(at,kind,payload) VALUES (?,?,?)", (utc_now(), kind, json.dumps(clean(value)))
        )
        self.db.commit()

    def add(self, kind: str, value) -> str:
        content = json.dumps(clean({"kind": kind, "observed_at": utc_now(), "data": value}), indent=2)
        encoded = content.encode()
        if self.used + len(encoded) > self.limit:
            raise ValueError("Evidence budget exhausted")
        identity = hashlib.sha256(encoded).hexdigest()
        write_private(self.path / "evidence" / f"{identity}.json", content + "\n")
        self.used += len(encoded)
        self.event(
            "evidence",
            {
                "id": identity,
                "sha256": hashlib.sha256(encoded + b"\n").hexdigest(),
                "bytes": len(encoded) + 1,
            },
        )
        return identity

    def cancelled(self) -> bool:
        return (self.path / "cancel").exists()

    def close(self):
        self.db.close()

    def manifest(self):
        entries = [
            json.loads(row[0])
            for row in self.db.execute("SELECT payload FROM events WHERE kind = 'evidence' ORDER BY id")
        ]
        write_private(
            self.path / "manifest.json",
            json.dumps({"run_id": self.run_id, "evidence": entries}, indent=2) + "\n",
        )


def verify(path: Path) -> dict:
    manifest = json.loads((path / "manifest.json").read_text())
    failures = []
    for entry in manifest["evidence"]:
        identity = entry["id"]
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("Invalid evidence identifier")
        evidence_path = path / "evidence" / f"{identity}.json"
        if evidence_path.is_symlink() or not evidence_path.is_file():
            failures.append(identity)
            continue
        with evidence_path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        if checksum != entry["sha256"]:
            failures.append(identity)
    return {
        "run_id": manifest["run_id"],
        "status": "failed" if failures else "verified",
        "checked": len(manifest["evidence"]),
        "failures": failures,
        "note": "Checks file integrity against the local manifest; this is not a signed attestation.",
    }


def read_state(path: Path) -> dict:
    with sqlite3.connect((path / "state.sqlite").resolve().as_uri() + "?mode=ro", uri=True) as db:
        return {key: json.loads(value) for key, value in db.execute("SELECT key,value FROM state")}


def read_evidence(path: Path, identity: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise ValueError("Invalid evidence identifier")
    descriptor = os.open(path / "evidence" / f"{identity}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024**2:
            raise ValueError("Evidence is not a bounded regular file")
        content = stream.read(8 * 1024**2 + 1)
    if hashlib.sha256(content.removesuffix(b"\n")).hexdigest() != identity:
        raise ValueError("Evidence integrity check failed")
    return clean(json.loads(content))
