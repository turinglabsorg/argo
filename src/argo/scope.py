import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from argo.contracts import Authorization, Engagement


class ScopeError(ValueError):
    pass


def origin(value: str) -> str:
    if re.search(r"[\s\\%*]", value):
        raise ScopeError("Ambiguous origin")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only exact HTTP(S) origins are supported")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ScopeError("Credentials, queries and fragments are not allowed in origins")
    if parsed.path not in {"", "/"}:
        raise ScopeError("Origins cannot contain a path")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    try:
        address = ipaddress.ip_address(host)
        if address.version == 6:
            host = f"[{address.compressed}]"
        else:
            host = str(address)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host) or host.startswith("0x") or host.endswith("."):
            raise ScopeError("Ambiguous numeric or trailing-dot hostname") from None
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ScopeError("Invalid hostname") from None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise ScopeError("Invalid port") from None
    return f"{parsed.scheme}://{host}:{port}"


def normalize(engagement: Engagement) -> Engagement:
    result = engagement.model_copy(deep=True)
    if not result.scope.repositories and not result.scope.web_origins:
        raise ScopeError("At least one explicit repository or web origin is required")
    result.scope.repositories = sorted(
        set(str(Path(p).expanduser().resolve(strict=True)) for p in result.scope.repositories)
    )
    for path in result.scope.repositories:
        root = Path(path)
        if not root.is_dir() or root == Path.home() or root == Path("/"):
            raise ScopeError("Select a specific repository directory")
    result.scope.web_origins = sorted(set(origin(p) for p in result.scope.web_origins))
    for prefix in result.scope.excluded_path_prefixes:
        if not prefix.startswith("/") or "%" in prefix or "\\" in prefix or ".." in prefix.split("/"):
            raise ScopeError("Excluded routes must be canonical absolute paths")
    if result.scope.http_methods != list(dict.fromkeys(result.scope.http_methods)):
        raise ScopeError("Duplicate HTTP methods")
    if any(m not in {"GET", "HEAD", "OPTIONS"} for m in result.scope.http_methods):
        raise ScopeError("This release supports read-only HTTP methods only")
    if result.actions.local_audit and not result.scope.repositories:
        raise ScopeError("Local audit requires an explicit repository")
    if (result.actions.web_observe or result.actions.web_validate) and not result.scope.web_origins:
        raise ScopeError("Web actions require an explicit origin")
    if result.actions.network_discovery or result.scope.network_ranges or result.scope.network_ports:
        raise ScopeError("Network scanning is not enabled in this release")
    if result.credential_refs:
        raise ScopeError("Authenticated target workflows are not enabled in this release")
    intel = result.intelligence
    if intel.disclosure.target_identifiers:
        raise ScopeError("Target identifier disclosure is not enabled")
    if intel.mode == "offline" and (
        intel.providers or intel.disclosure.cve_ids or intel.disclosure.public_package_versions
    ):
        raise ScopeError("Offline mode cannot enable disclosure or providers")
    return result


def digest(engagement: Engagement) -> str:
    spec = engagement.model_dump(exclude={"authorization"})
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load(path: Path) -> Engagement:
    if path.stat().st_size > 65536:
        raise ScopeError("Engagement file exceeds 64 KiB")
    return normalize(Engagement.model_validate_json(path.read_text()))


def authorize(engagement: Engagement, operator: str, reference: str, hours: int = 4) -> Engagement:
    result = normalize(engagement)
    if not operator.strip() or not reference.strip() or not 1 <= hours <= 24:
        raise ScopeError("An operator, authorization reference and 1–24 hour validity are required")
    now = datetime.now(timezone.utc)
    result.authorization = Authorization(
        status="authorized",
        approved_by=operator,
        reference=reference,
        approved_at=now.isoformat(),
        expires_at=(now + timedelta(hours=hours)).isoformat(),
        scope_sha256=digest(result),
    )
    return result


def check_authorization(engagement: Engagement):
    auth = engagement.authorization
    if (
        auth.status != "authorized"
        or not auth.reference
        or not auth.approved_by
        or auth.scope_sha256 != digest(engagement)
    ):
        raise ScopeError("Engagement is draft, changed, or lacks recorded authorization")
    try:
        start = datetime.fromisoformat(auth.approved_at or "")
        expiry = datetime.fromisoformat(auth.expires_at or "")
        now = datetime.now(timezone.utc)
        if not start.tzinfo or not expiry.tzinfo or not start <= now < expiry:
            raise ValueError
    except ValueError:
        raise ScopeError("Authorization is expired or has invalid dates") from None


def save(path: Path, engagement: Engagement):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ScopeError("Refusing to overwrite a symlink")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(engagement.model_dump_json(indent=2) + "\n")
    path.chmod(0o600)


def check_path(path: str, exclusions: list[str]) -> str:
    if not path.startswith("/") or "\\" in path or re.search(r"[\x00-\x20\x7f]", path):
        raise ScopeError("Invalid request path")
    decoded = unquote(path)
    if "%" in decoded or "\\" in decoded or re.search(r"[\x00-\x20\x7f]", decoded):
        raise ScopeError("Ambiguous encoded path")
    if ".." in decoded.split("/") or "." in decoded.split("/") or decoded.startswith("//"):
        raise ScopeError("Noncanonical request path")
    if any(decoded.startswith(prefix) for prefix in exclusions):
        raise ScopeError("Route excluded by engagement")
    return decoded
