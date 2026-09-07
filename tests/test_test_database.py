import subprocess
from pathlib import Path

import pytest

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
