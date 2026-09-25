"""
Gate 1 regression tests: scanner orchestration semantics.

Covers the two confirmed defects fixed this gate:

1. Bandit and Pylint never produced a ToolResult row at all (app.py never
   called db.session.add(ToolResult(...)) for them), so /security_issues's
   dedicated bandit/pylint parsers were permanently dead code and neither
   tool's outcome was queryable from the database - a scanner that ran
   (successfully or not) was indistinguishable from one that was never
   configured.
2. osv-scanner/license-check/every SCANNERS-dict tool silently produced no
   ToolResult row at all if the scanner call raised an exception - an
   errored scanner was, again, indistinguishable from one never attempted.

Runs the real run_bluescrub() path (not mocked) via a subprocess, the same
pattern as test_db_isolation.py, so it's isolated from the real database and
exercises genuine end-to-end orchestration rather than a stubbed scanner.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHILD_SCRIPT = Path(__file__).resolve().parent / '_orchestration_child.py'

# Every scanner currently wired into run_bluescrub(). license-check isn't in
# the historically-named "scanner set" (it has no executable/exit code of
# its own - see utils/license_analyzer.py, pure Python, no subprocess call)
# but it does produce a ToolResult row exactly like the others, so it's
# included here for the same reason the gate's own instructions call for:
# it's part of the active orchestration path.
EXPECTED_TOOL_NAMES = {
    'bandit', 'pylint', 'osv-scanner', 'license-check',
    'safety', 'semgrep', 'checkov', 'eslint', 'jshint',
    'trufflehog', 'tfsec', 'gitleaks',
}


def _run_orchestration_scan():
    env = dict(os.environ)
    env['FLASK_ENV'] = 'testing'
    proc = subprocess.run(
        [sys.executable, str(CHILD_SCRIPT)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, (
        f"orchestration child process failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.fixture(scope='module')
def orchestration_result():
    return _run_orchestration_scan()


def test_every_configured_scanner_produces_a_tool_result_row(orchestration_result):
    """No scanner attempt - successful, unavailable, or errored - may be
    invisible at the database layer. This is the core Gate 1 property."""
    seen_tool_names = {row['tool_name'] for row in orchestration_result['rows']}
    missing = EXPECTED_TOOL_NAMES - seen_tool_names
    assert not missing, (
        f"these configured scanners produced no ToolResult row at all: {missing}. "
        f"rows seen: {orchestration_result['rows']}"
    )


def test_bandit_and_pylint_rows_exist_and_are_shaped_for_the_existing_parser(orchestration_result):
    """Direct regression for the primary defect: bandit/pylint rows exist,
    and their content is plain text (not silently absent), matching what
    /security_issues's tool_name == 'bandit'/'pylint' branches already parse."""
    by_tool = {row['tool_name']: row for row in orchestration_result['rows']}
    assert 'bandit' in by_tool
    assert 'pylint' in by_tool
    # Plain text (or an explicit "ERROR: ..." string) - never empty/missing.
    assert by_tool['bandit']['result_prefix']
    assert by_tool['pylint']['result_prefix']


def test_scanner_ordering_is_deterministic_across_runs():
    """The same configured scanner set must execute in the same order on
    repeated runs (required orchestration property #1)."""
    first = _run_orchestration_scan()
    second = _run_orchestration_scan()

    first_order = [row['tool_name'] for row in first['rows']]
    second_order = [row['tool_name'] for row in second['rows']]
    assert first_order == second_order, (
        f"scanner execution order was not deterministic across runs:\n"
        f"  run 1: {first_order}\n  run 2: {second_order}"
    )
    # Sanity: this isn't trivially true because nothing ran.
    assert len(first_order) == len(EXPECTED_TOOL_NAMES)


def test_one_scanner_failure_does_not_stop_the_others(orchestration_result):
    """Required orchestration property #2 (failure isolation): every
    configured scanner still gets attempted even though several of them
    are not installed in this environment and will error/be unavailable."""
    assert orchestration_result['scan_success'] is True
    seen_tool_names = {row['tool_name'] for row in orchestration_result['rows']}
    assert seen_tool_names == EXPECTED_TOOL_NAMES


def test_security_issues_tool_result_parsing_does_not_crash_on_mixed_outcomes(orchestration_result):
    """/security_issues is the main consumer of ToolResult rows. Its
    ToolResult-parsing loop (bandit/pylint/osv-scanner/license-check
    branches) must not raise when scanners are unavailable/errored - e.g.
    the ERROR-marker JSON object osv-scanner/license-check now store on
    their except path, instead of the findings list a clean run stores.

    templates/security_issues.html does not exist in this repo at all (a
    separate, pre-existing bug, unrelated to ToolResult handling and out of
    this gate's scope) so the route itself always fails at the final
    render_template() call - that failure is asserted for explicitly and
    excluded, so this test only fails if something *else* raises."""
    exc = orchestration_result['security_issues_exception']
    assert exc == 'TemplateNotFound (pre-existing, unrelated)', (
        f"expected only the known, pre-existing missing-template failure, got: {exc!r} "
        f"(status={orchestration_result['security_issues_status']})"
    )
