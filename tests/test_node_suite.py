import pytest

from argo.workspace import Workspace

SOURCE = """const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
test('exclusive fixture', async () => {
  const lock = '/tmp/argo-node-suite-lock';
  assert.doesNotThrow(() => fs.mkdirSync(lock));
  try {
    await new Promise(resolve => setTimeout(resolve, DELAY));
    assert.ok(fs.statSync(lock).isDirectory());
  } finally {
    fs.rmdirSync(lock);
  }
});
"""


@pytest.mark.live
@pytest.mark.parametrize("delay_ms", [150, 26000])
def test_node_suite_serializes_shared_fixtures_and_budgets_the_whole_suite(delay_ms):
    source = SOURCE.replace("DELAY", str(delay_ms))
    with Workspace() as workspace:
        workspace.call("write", files={f"tests/argo-security/fixture-{i}.test.cjs": source for i in range(2)})
        result = workspace.call("node_tests")
        assert result["exit_code"] == 0, result
        assert "# pass 2" in result["stdout"]
        assert "# fail 0" in result["stdout"]
        assert "execution_limit" not in result
        assert workspace.active


@pytest.mark.live
def test_node_suite_limit_keeps_the_worker_for_retry():
    hanging = "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('control', () => {\n  console.log('x'.repeat(300000));\n  assert.equal(1, 1);\n});\n"
    valid = "const test = require('node:test');\nconst assert = require('node:assert/strict');\ntest('control', () => assert.equal(1, 1));\n"
    with Workspace() as workspace:
        workspace.call("write", files={"tests/argo-security/limited.test.cjs": hanging})
        result = workspace.call("node_tests")
        assert result["exit_code"] == 124, result
        assert result["execution_limit"] == "output"
        assert workspace.active
        workspace.call("write", files={"tests/argo-security/limited.test.cjs": valid})
        retried = workspace.call("node_tests")
        assert retried["exit_code"] == 0, retried
        assert "# pass 1" in retried["stdout"]
        assert workspace.active
