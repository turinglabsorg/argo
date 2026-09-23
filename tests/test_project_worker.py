"""The operator-built worker image that carries an audited project's declared dependencies."""

import json

import pytest

from argo import workspace as workspace_module
from argo.workspace import Workspace, project_worker, requirements_digest

BASE = "sha256:" + "a" * 64
IMAGE = "sha256:" + "b" * 64


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace_module, "PROJECT_WORKERS", tmp_path / "workers.json")
    monkeypatch.setattr(workspace_module, "worker_image", lambda: BASE)
    return tmp_path / "workers.json"


def entry(project, digest, requirements="requirements.txt", base=BASE, image=IMAGE):
    return {"image": image, "base": base, "requirements": requirements, "requirements_sha256": digest}


def project_with(tmp_path, text):
    project = tmp_path / "project"
    project.mkdir(parents=True)
    (project / "requirements.txt").write_text(text)
    return project


def test_only_plain_named_requirements_are_accepted(tmp_path):
    project = project_with(tmp_path, "# comment\n\nfastapi==0.115.0\nuvicorn[standard]==0.32.0\n")
    assert len(requirements_digest(project / "requirements.txt")) == 64
    for refused in (
        "--index-url https://packages.example.invalid/simple\nfastapi==0.115.0\n",
        "--extra-index-url https://packages.example.invalid/simple\n",
        "-f https://packages.example.invalid/wheels\n",
        "-e .\n",
        "./local-package\n",
        "git+https://example.invalid/pkg.git\n",
        "https://example.invalid/pkg-1.0-py3-none-any.whl\n",
        "-r other-requirements.txt\n",
        "-c constraints.txt\n",
        "--trusted-host packages.example.invalid\n",
    ):
        (project / "requirements.txt").write_text(refused)
        with pytest.raises(ValueError, match="plain package requirement"):
            requirements_digest(project / "requirements.txt")


def test_no_registry_keeps_the_stock_worker(tmp_path, registry):
    assert project_worker(None) is None
    assert project_worker(project_with(tmp_path, "fastapi==0.115.0\n")) is None
    registry.write_text(json.dumps({"projects": {}}))
    assert project_worker(project_with(tmp_path / "other", "fastapi==0.115.0\n")) is None


def test_recorded_image_is_used_and_must_stay_pinned(tmp_path, registry):
    project = project_with(tmp_path, "fastapi==0.115.0\n")
    digest = requirements_digest(project / "requirements.txt")
    registry.write_text(json.dumps({"projects": {str(project): entry(project, digest)}}))
    assert project_worker(project)["image"] == IMAGE
    assert Workspace(project=str(project)).image == IMAGE
    assert Workspace(project=str(project), image=BASE).image == BASE
    registry.write_text(json.dumps({"projects": {str(project): entry(project, digest, image="argo-worker:local")}}))
    with pytest.raises(ValueError, match="pinned to a local image digest"):
        project_worker(project)


def test_stale_dependencies_or_base_are_refused_instead_of_silently_tested(tmp_path, registry):
    project = project_with(tmp_path, "fastapi==0.115.0\n")
    digest = requirements_digest(project / "requirements.txt")
    registry.write_text(json.dumps({"projects": {str(project): entry(project, digest)}}))
    (project / "requirements.txt").write_text("fastapi==0.116.0\n")
    with pytest.raises(ValueError, match="no longer matches requirements.txt"):
        project_worker(project)
    (project / "requirements.txt").write_text("fastapi==0.115.0\n")
    registry.write_text(json.dumps({"projects": {str(project): entry(project, digest, base="sha256:" + "c" * 64)}}))
    with pytest.raises(ValueError, match="older base worker"):
        project_worker(project)
    registry.write_text(json.dumps({"projects": {str(project): entry(project, digest)}}))
    (project / "requirements.txt").unlink()
    with pytest.raises(ValueError, match="no longer matches"):
        project_worker(project)
