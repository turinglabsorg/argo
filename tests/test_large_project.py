"""The worker's map/selective-export contract that lets the coordinator slice a large project."""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from argo.workspace import Workspace

WORKER = Path(__file__).resolve().parents[1] / "src" / "argo" / "data" / "agent" / "worker.py"


def worker_module(root):
    """Load the worker outside its image; PyYAML only serves Node TAP parsing, unused here."""
    if "yaml" not in sys.modules:
        stub = types.ModuleType("yaml")
        stub.SafeLoader = type("SafeLoader", (), {})
        stub.YAMLError = type("YAMLError", (Exception,), {})
        stub.load = lambda *args, **kwargs: None
        sys.modules["yaml"] = stub
    spec = importlib.util.spec_from_file_location("argo_worker_under_test", WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.ROOT = str(root)
    return module


def large_tree(root, files=60, lines=800):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "access.py").write_text("def can_read(owner, actor):\n    return True\n")
    filler = "x = 'padding line for the working set budget'\n" * lines
    for index in range(files):
        (root / f"module_{index:02d}.py").write_text(filler)
    return root


def test_the_map_describes_the_whole_tree_without_its_contents(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    catalog = worker.file_map()
    assert catalog["file_count"] == 61
    assert catalog["total_bytes"] > 2 * 1024 * 1024
    assert catalog["truncated"] is False
    assert catalog["working_set_budget"] == {"max_files": worker.MAX_FILES, "max_bytes": worker.MAX_TOTAL}
    entry = next(item for item in catalog["files"] if item["path"] == "app/access.py")
    assert set(entry) == {"path", "bytes", "sha256", "reviewable"}
    assert len(entry["sha256"]) == 64


def test_a_whole_tree_export_still_fails_closed_over_budget(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    with pytest.raises(ValueError, match="export budget exceeded"):
        worker.files()


def test_a_selected_slice_returns_only_that_slice(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    selected = worker.files(["app/access.py", "module_00.py"])
    assert sorted(selected) == ["app/access.py", "module_00.py"]
    assert "can_read" in selected["app/access.py"]


def test_a_slice_skips_what_it_cannot_read_instead_of_failing(tmp_path):
    """code.edit exports its targets before writing them, and a new test file does not exist yet."""
    root = large_tree(tmp_path)
    (root / "tests").mkdir()
    (root / "logo.bin").write_bytes(b"\x00\xff\xfe binary")
    worker = worker_module(root)
    selected = worker.files([
        "app/access.py",
        "tests/argo-security/test_new_regression.py",
        "tests/argo-security/test_new_positive_control.py",
        "missing.py",
        "logo.bin",
    ])
    assert sorted(selected) == ["app/access.py"]
    with pytest.raises(ValueError):
        worker.files(["../outside.py"])


def test_a_slice_over_the_working_set_budget_is_refused(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    with pytest.raises(ValueError, match="content budget"):
        worker.files([f"module_{index:02d}.py" for index in range(60)])


def test_a_slice_with_too_many_files_is_refused(tmp_path):
    root = tmp_path / "many"
    root.mkdir()
    for index in range(20):
        (root / f"f{index}.py").write_text("x = 1\n")
    worker = worker_module(root)
    worker.MAX_FILES = 5
    with pytest.raises(ValueError, match="file budget"):
        worker.files([f"f{index}.py" for index in range(20)])


def test_a_slice_cannot_escape_the_workspace(tmp_path):
    worker = worker_module(large_tree(tmp_path))
    for escape in ("../outside.py", "/etc/passwd", "app/../../outside.py"):
        with pytest.raises(ValueError):
            worker.files([escape])


def test_the_map_skips_excluded_directories(tmp_path):
    root = tmp_path / "project"
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("value = 1\n")
    worker = worker_module(root)
    assert [item["path"] for item in worker.file_map()["files"]] == ["src/app.py"]


@pytest.mark.live
def test_a_mounted_large_project_exposes_map_and_slices_through_the_worker(tmp_path):
    """The contract the coordinator relies on, exercised against the real container."""
    root = large_tree(tmp_path / "project")
    with Workspace(project=root) as workspace:
        with pytest.raises(ValueError, match="export budget exceeded"):
            workspace.call("export")
        catalog = workspace.call("map")
        assert catalog["file_count"] == 61
        assert all("content" not in entry for entry in catalog["files"])
        sliced = workspace.call("export", paths=["app/access.py"])["files"]
        assert list(sliced) == ["app/access.py"]
        assert "can_read" in sliced["app/access.py"]
        with pytest.raises(ValueError, match="budget"):
            workspace.call("export", paths=[f"module_{index:02d}.py" for index in range(60)])
        assert workspace.active
