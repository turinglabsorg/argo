"""Fixed pytest outcome collector, executed only inside the isolated worker."""

import json
import sys
from pathlib import Path

import pytest


class Results:
    def __init__(self):
        self.tests = 0
        self.phases = []
        self.collection_errors = 0

    def pytest_collection_finish(self, session):
        self.tests = len(session.items)

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors += 1

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        result = yield
        report = result.get_result()
        self.phases.append({
            "phase": call.when, "outcome": report.outcome,
            "assertion": bool(call.excinfo and isinstance(call.excinfo.value, AssertionError)),
            "xfail": hasattr(report, "wasxfail"),
        })


if __name__ == "__main__":
    sys.path.insert(0, "/workspace")
    results = Results()
    # A dedicated test is Argo's own, not a case in the audited suite. Without a cut-off pytest
    # collects every conftest above it, so an audited project whose tests/conftest.py imports the
    # application decides, at collection time, whether any finding can ever be verified: its import
    # runs before the dedicated test can prepare its own environment, and every case comes back
    # inconclusive. That conftest is also untrusted code running inside Argo's verification.
    target = Path(sys.argv[1])
    arguments = ["-q", "-p", "no:cacheprovider", "--confcutdir", str(target.parent), sys.argv[1]]
    code = pytest.main(arguments, plugins=[results])
    Path(sys.argv[2]).write_text(json.dumps({"tests": results.tests, "collection_errors": results.collection_errors, "phases": results.phases}))
    sys.exit(code)
