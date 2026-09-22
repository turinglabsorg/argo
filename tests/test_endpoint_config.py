import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_providers import endpoint

import argo.agent_models as agent_models
import argo.chat as chat
import argo.finding_review as finding_review
import argo.inference as inference
from argo.agent_models import QWEN, review_context_window, review_response, select_context_limit, structured
from argo.config import ProjectConfig, apply, load_project_config, resolve
from argo.inference import (
    DEFAULT_ENDPOINT,
    check_endpoint,
    connect_timeout,
    local_models,
    loopback_endpoint,
    select_endpoint,
)
from argo.inference import (
    endpoint as current_endpoint,
)
from argo.providers import CodingProfile, ModelSettings, load_settings, save_profile

SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}
MESSAGES = [{"role": "system", "content": "System"}, {"role": "user", "content": "Task"}]


@pytest.fixture(autouse=True)
def restore_selection():
    previous = (inference.ENDPOINT, agent_models.CONTEXT_LIMIT, finding_review.REVIEWER)
    yield
    inference.ENDPOINT, agent_models.CONTEXT_LIMIT, finding_review.REVIEWER = previous


def settings_file(tmp_path, **values):
    path = tmp_path / "models.json"
    document = {
        "active": "Local",
        "profiles": [
            {"name": "Local", "protocol": "ollama", "base_url": DEFAULT_ENDPOINT, "model": "argo-coder:30b-a3b"},
            {"name": "Omen Qwen", "protocol": "ollama", "base_url": "http://100.64.0.9:11434", "model": "argo-qwen:27b"},
        ],
        **values,
    }
    path.write_text(json.dumps(document))
    return path


def project_with(tmp_path, document):
    project = tmp_path / "project"
    (project / ".argo").mkdir(parents=True)
    (project / ".argo" / "configs.json").write_text(json.dumps(document))
    return project


def test_specialist_inference_follows_the_selected_endpoint():
    """The reviewer path must resolve the endpoint per request, not at import time."""
    with endpoint("ollama", replies=[{"ok": True}]) as (profile, records):
        assert select_endpoint(profile.base_url) == profile.base_url
        assert structured(QWEN, MESSAGES, SCHEMA) == {"ok": True}
    assert [record["path"] for record in records] == ["/api/show", "/api/chat"]
    assert records[-1]["body"]["model"] == QWEN


def test_discovery_and_chat_follow_the_selected_endpoint():
    with endpoint("ollama", replies=[{"ok": True}]) as (profile, records):
        select_endpoint(profile.base_url)
        assert [item["name"] for item in local_models()] == []
        assert current_endpoint() == profile.base_url
        assert chat.endpoint() == profile.base_url
        assert inference.endpoint() == profile.base_url
    assert records[0]["method"] == "GET"
    assert records[0]["path"] == "/api/tags"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1:11434",
        "http://user:secret@omen:11434",
        "http://omen:11434?token=abc",
        "http://omen:11434#fragment",
        "not-a-url",
        "",
    ],
)
def test_endpoint_validation_rejects_unusable_urls(url):
    with pytest.raises(ValueError):
        check_endpoint(url)


def test_endpoint_validation_normalizes_and_accepts_remote_hosts():
    assert check_endpoint(" http://100.64.0.9:11434/ ") == "http://100.64.0.9:11434"
    assert check_endpoint("https://inference.example/v1") == "https://inference.example/v1"


def test_connect_timeout_expands_for_non_loopback_endpoints():
    assert loopback_endpoint(DEFAULT_ENDPOINT)
    assert loopback_endpoint("http://localhost:11434")
    assert not loopback_endpoint("http://100.64.0.9:11434")
    assert connect_timeout(DEFAULT_ENDPOINT) == 3
    assert connect_timeout("http://100.64.0.9:11434") == 15


def test_context_limit_caps_the_advertised_capacity():
    metadata = {"model_info": {"general.architecture": "qwen35", "qwen35.context_length": 262144}}
    select_context_limit(None)
    unbounded = review_context_window(QWEN, MESSAGES, SCHEMA, metadata)
    select_context_limit(65536)
    assert review_context_window(QWEN, MESSAGES, SCHEMA, metadata) <= 65536
    assert unbounded >= 32768


def test_context_limit_reports_a_blocker_instead_of_exhausting_the_device():
    metadata = {"model_info": {"general.architecture": "qwen35", "qwen35.context_length": 262144}}
    select_context_limit(2048)
    with pytest.raises(agent_models.LocalModelError) as error:
        review_context_window(QWEN, MESSAGES, SCHEMA, metadata)
    assert error.value.category == "context"


def test_context_limit_rejects_values_outside_the_supported_range():
    for value in (0, 512, "65536", 10**9):
        with pytest.raises(ValueError):
            select_context_limit(value)


def test_remote_reviewer_runs_through_the_configured_provider():
    with endpoint("openai", replies=[{"ok": True}], json_response=True) as (profile, records):
        assert review_response(QWEN, MESSAGES, SCHEMA, lambda: None, profile=profile) == {"ok": True}
    assert records[-1]["body"]["model"] == "custom-model"
    assert records[-1]["path"].endswith("/chat/completions")


def test_resolved_settings_expose_reviewer_profiles(tmp_path):
    path = settings_file(tmp_path, reviewers={"qwen": "Omen Qwen"}, local_context_limit=65536)
    resolved = resolve(None, path)
    assert resolved.reviewers["qwen"].model == "argo-qwen:27b"
    assert resolved.local_context_limit == 65536
    assert resolved.policy()["reviewers"] == {"qwen": "argo-qwen:27b"}


def test_remote_inference_is_recorded_as_a_coverage_gap(tmp_path):
    path = settings_file(tmp_path, reviewers={"qwen": "Omen Qwen"}, local_endpoint="http://100.64.0.9:11434")
    resolved = resolve(None, path)
    assert resolved.policy()["local_endpoint_scope"] == "remote_host"
    notes = " ".join(resolved.gaps())
    assert "100.64.0.9" in notes
    assert "sent to that" in notes


def test_loopback_inference_records_no_gap(tmp_path):
    resolved = resolve(None, settings_file(tmp_path))
    assert resolved.gaps() == []
    assert resolved.policy()["local_endpoint_scope"] == "loopback"


def test_project_configuration_selects_a_globally_defined_profile(tmp_path):
    path = settings_file(tmp_path)
    project = project_with(tmp_path, {"coding": "Omen Qwen", "reviewers": {"qwen": "Omen Qwen"}})
    resolved = resolve(project, path)
    assert resolved.coding.name == "Omen Qwen"
    assert resolved.reviewers["qwen"].name == "Omen Qwen"
    assert resolved.sources["project"].endswith(".argo/configs.json")


def test_project_configuration_cannot_define_endpoints_or_credentials():
    for document in (
        {"reviewers": {"qwen": "Omen"}, "local_endpoint": "http://attacker.invalid"},
        {"base_url": "http://attacker.invalid"},
        {"credential": "OPENROUTER"},
        {"profiles": [{"name": "Rogue", "base_url": "http://attacker.invalid"}]},
    ):
        with pytest.raises(ValidationError):
            ProjectConfig.model_validate(document)


def test_project_configuration_rejects_unknown_profile_names(tmp_path):
    path = settings_file(tmp_path)
    project = project_with(tmp_path, {"reviewers": {"qwen": "Undefined"}})
    with pytest.raises(ValueError, match="only select profiles you already configured"):
        resolve(project, path)


def test_project_configuration_rejects_unknown_roles(tmp_path):
    path = settings_file(tmp_path)
    project = project_with(tmp_path, {"reviewers": {"coder": "Omen Qwen"}})
    with pytest.raises(ValidationError):
        resolve(project, path)


def test_project_configuration_rejects_symlinks(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"coding": "Omen Qwen"}))
    project = tmp_path / "project"
    (project / ".argo").mkdir(parents=True)
    os.symlink(target, project / ".argo" / "configs.json")
    with pytest.raises(ValueError, match="symlinked"):
        load_project_config(project)


def test_project_configuration_rejects_oversized_and_malformed_files(tmp_path):
    project = project_with(tmp_path, {"coding": "Omen Qwen"})
    (project / ".argo" / "configs.json").write_text("{" + " " * 17000)
    with pytest.raises(ValueError, match="size budget"):
        load_project_config(project)
    (project / ".argo" / "configs.json").write_text("not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_project_config(project)


def test_missing_project_configuration_falls_back_to_global_settings(tmp_path):
    path = settings_file(tmp_path)
    project = tmp_path / "bare"
    project.mkdir()
    resolved = resolve(project, path)
    assert resolved.coding.name == "Local"
    assert resolved.sources["project"] is None


def test_apply_selects_endpoint_context_and_reviewer(tmp_path):
    path = settings_file(
        tmp_path, reviewers={"qwen": "Omen Qwen"}, local_endpoint="http://100.64.0.9:11434", local_context_limit=32768
    )
    apply(resolve(None, path))
    assert inference.endpoint() == "http://100.64.0.9:11434"
    assert agent_models.CONTEXT_LIMIT == 32768
    assert finding_review.reviewer_model() == "argo-qwen:27b"
    assert finding_review.reviewer_label() == "Omen Qwen"


def test_saving_a_profile_preserves_endpoint_and_reviewer_settings(tmp_path):
    path = settings_file(
        tmp_path, reviewers={"qwen": "Omen Qwen"}, local_endpoint="http://100.64.0.9:11434", local_context_limit=65536
    )
    save_profile(CodingProfile(name="Added", protocol="openai", base_url="https://example.invalid/v1", model="m"), path)
    saved = load_settings(path)
    assert saved.local_endpoint == "http://100.64.0.9:11434"
    assert saved.local_context_limit == 65536
    assert saved.reviewers == {"qwen": "Omen Qwen"}
    assert saved.active == "Added"


def test_settings_reject_reviewers_without_a_matching_profile():
    with pytest.raises(ValueError, match="existing profile"):
        ModelSettings(reviewers={"qwen": "Missing"})


def test_default_settings_keep_inference_on_this_computer():
    settings = ModelSettings()
    assert settings.local_endpoint == DEFAULT_ENDPOINT
    assert settings.reviewers == {}
    assert loopback_endpoint(settings.local_endpoint)
    assert Path(".argo/configs.json").name == "configs.json"


def test_project_configuration_drives_the_actual_review_request(tmp_path):
    """End to end: a project selection must reach the HTTP request the reviewer makes."""
    with endpoint("openai", replies=[{"ok": True}], json_response=True) as (fixture, records):
        path = tmp_path / "models.json"
        path.write_text(json.dumps({
            "active": "Local",
            "profiles": [
                {"name": "Local", "protocol": "ollama", "base_url": DEFAULT_ENDPOINT, "model": "argo-coder:30b-a3b"},
                {"name": "Remote Abliterated", "protocol": fixture.protocol, "base_url": fixture.base_url, "model": fixture.model},
            ],
        }))
        project = project_with(tmp_path, {"reviewers": {"qwen": "Remote Abliterated"}})
        apply(resolve(project, path))
        assert finding_review.reviewer_model() == fixture.model
        assert review_response(QWEN, MESSAGES, SCHEMA, lambda: None, profile=finding_review.REVIEWER) == {"ok": True}
    assert records[-1]["body"]["model"] == fixture.model
    assert records[-1]["path"].endswith("/chat/completions")
