import hashlib
import runpy
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_providers import endpoint

from argo.agent_models import QWEN


def test_owned_review_controls_execute_and_evaluation_saves_results(tmp_path, monkeypatch):
    script = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/evaluate_reviewers.py'))
    rubric = script['verify_controls']()
    assert len(rubric['positive']) == len(rubric['negative']) == 2
    final = {'summary': 'Fixture review', 'suspected_findings': []}
    with endpoint('ollama', replies=[final]) as (profile, records):
        monkeypatch.setattr('argo.agent_models.ENDPOINT', profile.base_url)
        report = script['evaluate']([QWEN], tmp_path / 'evaluation')
    assert len(report['source_sha256']) == 4
    assert report['reviews'][0]['result']['status'] == 'complete'
    assert any(record['path'] == '/api/chat' for record in records)
    assert (tmp_path / 'evaluation/report.json').stat().st_mode & 0o777 == 0o600


def test_installer_reuses_only_verified_local_artifacts(tmp_path):
    script = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/install_models.py'))
    payload = b'owned synthetic model artifact'
    model = {'filename': 'fixture.gguf', 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
    cache, ollama = tmp_path / 'cache', tmp_path / 'ollama'
    cache.mkdir()
    (ollama / 'blobs').mkdir(parents=True)
    blob = ollama / 'blobs' / ('sha256-' + model['sha256'])
    blob.write_bytes(payload)
    assert script['cached_artifact'](model, cache, ollama) == blob
    artifact = cache / model['filename']
    artifact.write_bytes(payload)
    assert script['cached_artifact'](model, cache, ollama) == artifact
    artifact.write_bytes(b'x' * len(payload))
    assert script['cached_artifact'](model, cache, ollama) == blob
    blob.write_bytes(b'x' * len(payload))
    assert script['cached_artifact'](model, cache, ollama) is None
    artifact.unlink()
    artifact.symlink_to(blob)
    blob.write_bytes(payload)
    assert script['cached_artifact'](model, cache, ollama) == blob


def test_installer_checks_conversion_space_before_downloading(tmp_path, monkeypatch):
    script = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/install_models.py'))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    monkeypatch.setattr(sys, 'argv', ['install_models.py', '--model', 'argo-qwen:27b'])
    with pytest.raises(RuntimeError, match='temporary validation copies'):
        script['main']()
