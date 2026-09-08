from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Authorization(Contract):
    status: Literal["draft", "authorized"] = "draft"
    approved_by: str | None = None
    reference: str | None = None
    approved_at: str | None = None
    expires_at: str | None = None
    scope_sha256: str | None = None


class Scope(Contract):
    repositories: list[str] = []
    web_origins: list[str] = []
    network_ranges: list[str] = []
    network_ports: list[int] = []
    excluded_path_prefixes: list[str] = ["/logout", "/payments"]
    http_methods: list[str] = ["GET", "HEAD", "OPTIONS"]


class Actions(Contract):
    local_audit: bool = True
    web_observe: bool = False
    web_validate: bool = False
    network_discovery: bool = False


class Disclosure(Contract):
    cve_ids: bool = False
    public_package_versions: bool = False
    target_identifiers: bool = False


class Intelligence(Contract):
    mode: Literal["offline", "connected"] = "offline"
    providers: list[Literal["nvd", "epss", "cisa_kev", "osv"]] = []
    disclosure: Disclosure = Field(default_factory=Disclosure)


class Limits(Contract):
    max_model_actions: int = Field(default=30, ge=1, le=100)
    max_parallel_tools: int = Field(default=2, ge=1, le=4)
    max_tool_seconds: int = Field(default=300, ge=1, le=600)
    max_requests_per_second_per_target: float = Field(default=2.0, gt=0, le=10)
    max_total_target_requests: int = Field(default=500, ge=1, le=10000)
    max_evidence_mib: int = Field(default=250, ge=1, le=1024)


class CredentialRef(Contract):
    name: str
    hush_ref: str
    origin: str
    role: str


class Engagement(Contract):
    schema_version: Literal["0.1"] = "0.1"
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    purpose: str = Field(min_length=1, max_length=1000)
    authorization: Authorization = Field(default_factory=Authorization)
    scope: Scope = Field(default_factory=Scope)
    actions: Actions = Field(default_factory=Actions)
    intelligence: Intelligence = Field(default_factory=Intelligence)
    limits: Limits = Field(default_factory=Limits)
    credential_refs: list[CredentialRef] = []


class ApplicabilityReview(Contract):
    model: str
    assessment: Literal["potentially_applicable", "not_applicable", "insufficient_context"]
    reason: str
    prerequisites: str
    test_plan: str
    evidence_id: str


class FindingReview(Contract):
    model: str
    phase: Literal["finding", "fix"]
    proposed_verdict: Literal["reproduced", "refuted", "fixed"]
    status: Literal["complete", "failed"]
    decision: Literal["agree", "disagree", "insufficient_context"]
    summary: str
    evidence_id: str
    test_evidence_id: str
    context_sha256: str
    test_assessment: str = ""
    remaining_concerns: list[str] = []


class FindingReproduction(Contract):
    test_evidence_id: str
    verdict_evidence_id: str
    source_hashes: dict[str, str]
    test_hashes: dict[str, str]
    support_hashes: dict[str, str] = {}
    source_paths: list[str]
    tests: dict[str, str] = {}


class FindingVerification(Contract):
    state: Literal["pending", "tested", "reproduced", "refuted", "fixed", "inconclusive", "stale"] = "pending"
    explanation: str = ""
    evidence_ids: list[str] = []
    test_evidence_id: str | None = None
    source_hashes: dict[str, str] = {}
    test_hashes: dict[str, str] = {}
    source_paths: list[str] = []
    tests: dict[str, str] = {}
    support_hashes: dict[str, str] = {}
    reproduction: FindingReproduction | None = None
    reviews: list[FindingReview] = []


class Finding(Contract):
    id: str
    asset: str
    rule: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    status: Literal["suspected", "confirmed", "rejected", "inconclusive"] = "suspected"
    line: int | None = None
    cwe: str | None = None
    evidence_ids: list[str] = []
    supporting_rules: list[str] = []
    explanation: str
    remediation: str
    validation: str | None = None
    advisory_ids: list[str] = []
    assessments: list[ApplicabilityReview] = []
    verification: FindingVerification = Field(default_factory=FindingVerification)


class Package(Contract):
    ecosystem: Literal["npm", "PyPI"]
    name: str
    version: str
    asset: str


class Proposal(Contract):
    finding_id: str
    action: Literal["explain", "review_evidence"]
    evidence_ids: list[str] = Field(min_length=1, max_length=10)
    explanation: str = Field(min_length=1, max_length=3000)
    next_check: str = Field(max_length=1000)


def utc_now() -> str:
    return datetime.now().astimezone().isoformat()
