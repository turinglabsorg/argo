import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from argo.agent_models import select_context_limit
from argo.finding_review import select_reviewer
from argo.inference import DEFAULT_ENDPOINT, loopback_endpoint, select_endpoint
from argo.providers import SETTINGS, load_settings

PROJECT_CONFIG = Path(".argo") / "configs.json"
MAX_CONFIG_BYTES = 16000
ROLES = ("qwen", "foundation", "vulnllm")


class ConfigError(ValueError):
    """Operator-facing configuration failure. Its message names settings, never project source."""


class ProjectConfig(BaseModel):
    """Per-project selection. It may only name profiles already defined by the operator."""

    model_config = ConfigDict(extra="forbid")
    coding: str | None = Field(default=None, min_length=1, max_length=80)
    reviewers: dict[Literal["qwen", "foundation", "vulnllm"], str] = Field(default_factory=dict)


@dataclass(frozen=True)
class Resolved:
    coding: object
    reviewers: dict
    local_endpoint: str = DEFAULT_ENDPOINT
    local_context_limit: int | None = None
    sources: dict = field(default_factory=dict)

    def policy(self):
        return {
            "local_endpoint": self.local_endpoint,
            "local_endpoint_scope": "loopback" if loopback_endpoint(self.local_endpoint) else "remote_host",
            "local_context_limit": self.local_context_limit,
            "reviewers": {role: profile.model for role, profile in self.reviewers.items()},
            "sources": self.sources,
        }

    def gaps(self):
        notes = []
        if not loopback_endpoint(self.local_endpoint):
            notes.append(
                "Specialist inference ran on the operator-selected host " + self.local_endpoint
                + " instead of this computer. Project source under review was sent to that host."
            )
        for role, profile in self.reviewers.items():
            if profile.protocol != "ollama" or not loopback_endpoint(profile.base_url):
                notes.append(
                    f"The {role} reviewer ran on the operator-selected endpoint {profile.base_url}"
                    f" using model {profile.model}. Review payloads, including project source,"
                    " test output and evidence, were sent to that endpoint."
                )
        return notes


def project_config_path(project):
    return Path(project) / PROJECT_CONFIG


def load_project_config(project):
    if project is None:
        return None
    path = project_config_path(project)
    if path.is_symlink():
        raise ConfigError("Refusing a symlinked project configuration: " + str(path))
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError("Project configuration exceeds its size budget: " + str(path))
    try:
        document = json.loads(path.read_text())
    except ValueError as exc:
        raise ConfigError("Project configuration is not valid JSON: " + str(path)) from exc
    return ProjectConfig.model_validate(document)


def resolve(project=None, path=SETTINGS):
    settings = load_settings(path)
    sources = {"global": str(path), "project": None}
    coding, reviewers = settings.coding, {}
    for role in ROLES:
        profile = settings.reviewer(role)
        if profile is not None:
            reviewers[role] = profile
    override = load_project_config(project)
    if override is not None:
        sources["project"] = str(project_config_path(project))
        names = {profile.name: profile for profile in settings.profiles}
        selected = [override.coding, *override.reviewers.values()]
        unknown = sorted({name for name in selected if name is not None} - set(names))
        if unknown:
            raise ConfigError(
                "The project configuration names profiles that are not defined in "
                + str(path)
                + ": "
                + ", ".join(unknown)
                + ". A project can only select profiles you already configured."
            )
        if override.coding:
            coding = names[override.coding]
        for role, name in override.reviewers.items():
            reviewers[role] = names[name]
    return Resolved(
        coding=coding,
        reviewers=reviewers,
        local_endpoint=settings.local_endpoint,
        local_context_limit=settings.local_context_limit,
        sources=sources,
    )


def apply(resolved):
    select_endpoint(resolved.local_endpoint)
    select_context_limit(resolved.local_context_limit)
    select_reviewer(resolved.reviewers.get("qwen"))
    return resolved
