import json
from pathlib import Path

import pytest
from test_providers import endpoint

from argo.agent import run_agent


@pytest.mark.live
@pytest.mark.parametrize("explicit", [None, 2])
def test_project_inventory_can_be_read_before_findings_without_overriding_explicit_limit(tmp_path, explicit):
    project = tmp_path / "project"
    project.mkdir()
    paths = [f"module_{index}.py" for index in range(26)]
    for name in paths:
        (project / name).write_text("value = 1\n")
    actions = [{"action": "workspace.read", "parameters": {"path": name}} for name in paths]
    actions.append({"action": "finish", "parameters": {"summary": "All fixture files were read; no security coverage claim."}})
    with endpoint("openai", replies=actions, metadata={"context_length": 131072}) as (coding, _):
        result = run_agent("Read the complete owned project inventory", tmp_path / "runs", project=project,
                           coding=coding, use_mcp=False, max_steps=explicit)
    report = json.loads((Path(result["report"]).parent / "report.json").read_text())
    assert result["status"] == ("complete" if explicit is None else "incomplete")
    assert sum(event["tool"] == "workspace.read" for event in report["tools"]) == (26 if explicit is None else explicit)
    assert all((project / name).read_text() == "value = 1\n" for name in paths)
