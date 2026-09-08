import subprocess
from pathlib import Path

import pytest
from test_providers import endpoint

from argo.agent import run_agent
from argo.controller import Cancelled
from argo.test_database import database_mode
from argo.workspace import Workspace


def test_test_database_rejects_arbitrary_configuration():
    for mode in ["host", "postgres", "mongodb://example.com", ""]:
        with pytest.raises(ValueError):
            database_mode(mode)
    assert database_mode("off") == "off"


@pytest.mark.live
def test_mongodb_real_crud_isolation_freshness_and_cleanup():
    probe = (Path(__file__).parent / "fixtures/mongodb_probe.py").read_text()
    names = []
    for _ in range(2):
        with Workspace(test_database="mongodb") as workspace:
            names += [workspace.name, workspace.database_name]
            assert workspace.inspect()["HostConfig"]["NetworkMode"] == "none"
            workspace.call("write", files={"probe.py": probe})
            result = workspace.call("python", path="probe.py")
            assert result["exit_code"] == 0, result
            assert "insert/find" in result["stdout"]
        for name in names:
            assert subprocess.run(["docker", "inspect", name], capture_output=True).returncode != 0


@pytest.mark.live
def test_fixture_reset_is_empty_preserves_files_and_requires_explicit_selection(tmp_path):
    with Workspace() as workspace:
        with pytest.raises(ValueError, match='operator-selected'):
            workspace.reset_test_database()
    probe = (Path(__file__).parent / 'fixtures/mongodb_probe.py').read_text()
    actions = [
        {'action': 'python.run', 'parameters': {'path': 'probe.py'}},
        {'action': 'test.database.reset', 'parameters': {}},
        {'action': 'python.run', 'parameters': {'path': 'probe.py'}},
        {'action': 'finish', 'parameters': {'summary': 'The same fixture probe passes before and after reset'}},
    ]
    with endpoint('openai', replies=actions, metadata={'context_length': 131072}) as (coding, _):
        result = run_agent('Check isolated fixture reset', tmp_path / 'runs', seed={'probe.py': probe}, coding=coding, use_mcp=False, test_database='mongodb', max_steps=4)
    assert result['status'] == 'complete', result
    assert (Path(result['report']).parent / 'code/probe.py').read_text() == probe


@pytest.mark.live
def test_mongodb_cleanup_after_start_failure_and_cancellation(monkeypatch):
    def failed_start(*args):
        raise RuntimeError("fixture startup failed")

    with monkeypatch.context() as patch:
        patch.setattr("argo.workspace.start_mongodb", failed_start)
        failed = Workspace(test_database="mongodb")
        with pytest.raises(RuntimeError, match="fixture startup failed"):
            with failed:
                pass
        assert not failed.active
        assert subprocess.run(["docker", "inspect", failed.name], capture_output=True).returncode != 0
    with pytest.raises(RuntimeError, match="fixture startup failed"):
        with Workspace(test_database="mongodb") as resetting:
            with monkeypatch.context() as patch:
                patch.setattr("argo.workspace.start_mongodb", failed_start)
                resetting.reset_test_database()
    assert not resetting.active
    assert not resetting.database_started
    for name in [resetting.name, resetting.database_name]:
        assert subprocess.run(["docker", "inspect", name], capture_output=True).returncode != 0
    stopped = False

    def check():
        if stopped:
            raise Cancelled("Owned cancellation control")

    with Workspace(check, test_database="mongodb") as workspace:
        stopped = True
        with pytest.raises(Cancelled):
            workspace.call("export")
        assert not workspace.active
        assert not workspace.database_started
    for name in [workspace.name, workspace.database_name]:
        assert subprocess.run(["docker", "inspect", name], capture_output=True).returncode != 0
