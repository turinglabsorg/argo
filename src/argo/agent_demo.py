from argo.agent import run_agent
from argo.agent_models import ANALYST, REVIEWER
from argo.workspace import Workspace

SEED = {
    "app.py": '''def find_user(connection, name):
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    return connection.execute(query).fetchall()
''',
    "README.md": """# Owned SQL injection fixture

`app.find_user(connection, name)` returns `(id, name)` rows from an existing SQLite
connection. The caller owns the connection; the function must not open a database,
change rows, or change the schema. The users table has `id INTEGER, name TEXT`.
Preserve this API and normal lookups, including names containing apostrophes.
All data is synthetic. This lab runs only inside an offline disposable container.
""",
}
TASK = """Audit and repair the owned SQLite fixture. Follow this checklist in order:
1. Read app.py and README.md.
2. Call mcp.read_wiki_structure for python/cpython, if available.
3. Ask security.review with foundation, then with vulnllm, to review app.py.
4. Run bandit.scan on the vulnerable code.
5. Use code.edit to create ONLY tests/test_app.py. Write three pytest tests for
app.find_user(connection, name). Each test uses sqlite3.connect(':memory:') with
a users(id INTEGER, name TEXT) table seeded with Alice and Bob. Check that Alice
returns [(1, 'Alice')], an unknown name returns [], and the SQL injection input
"' OR 1=1 --" returns []. Do not change app.py yet.
6. Run python.tests. The injection assertion must fail on the vulnerable code.
7. Use code.edit to fix ONLY app.py with parameterized SQL, preserving its API.
8. Run python.tests again, then bandit.scan again. Keep the injection assertion.
9. If tests fail, inspect the failing assertion. Correct mistaken fixtures if
needed, without weakening security checks; rerun tests after every edit.
10. Finish with the observed results. Avoid further model reviews after the fix;
test evidence is the validation. An independent verifier will check more inputs.
"""
VERIFY = '''import sqlite3
from app import find_user

connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE users (id INTEGER, name TEXT)")
connection.executemany("INSERT INTO users VALUES (?, ?)", [(1, "Alice"), (2, "Bob"), (3, "O'Reilly")])
assert find_user(connection, "Alice") == [(1, "Alice")]
assert find_user(connection, "Nobody") == []
assert find_user(connection, "O'Reilly") == [(3, "O'Reilly")]
assert find_user(connection, "' OR 1=1 --") == []
assert find_user(connection, "Alice' OR '1'='1") == []
assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
print("Independent SQL injection, positive, negative and data-integrity controls passed")
'''


def independent_validation(files, events, check):
    with Workspace(check) as workspace:
        for offset in range(0, len(files), 20):
            workspace.call("write", files=dict(list(files.items())[offset:offset + 20]))
        workspace.call("write", files={"independent_validation.py": VERIFY})
        validation = workspace.call("python", path="independent_validation.py")
    tests = [item for item in events if item["tool"] == "python.tests"]
    validation["observed_failing_then_passing_tests"] = bool(tests and tests[0]["exit_code"] == 1 and tests[-1]["exit_code"] == 0)
    validation["regression_tests_unchanged"] = bool(tests and tests[0]["test_hashes"] and tests[0]["test_hashes"] == tests[-1]["test_hashes"])
    validation["production_code_changed"] = files.get("app.py") != SEED["app.py"]
    validation["passed"] = validation["exit_code"] == 0 and validation["observed_failing_then_passing_tests"] and validation["production_code_changed"] and validation["regression_tests_unchanged"]
    return validation


def demo(state_root, **options):
    return run_agent(TASK, state_root, seed=SEED, validation=independent_validation, required_reviews=(ANALYST, REVIEWER), **options)
