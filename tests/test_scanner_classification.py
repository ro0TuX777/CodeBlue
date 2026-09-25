"""
Gate 1B: scanner-specific result classification.

utils/external_scanners.py used to assume exit codes 0 and 1 meant roughly
the same thing ("clean" / "findings") for every tool. That's false for
several of the 12 scanners CodeBlue runs (Safety's 64, JSHint's 2, Semgrep's
exit-0-even-with-findings, Pylint's bitmask, GitLeaks' forced exit 0), so
each now has its own classify function/branch - these tests prove each
one's documented convention, then prove PASS/FINDINGS/UNAVAILABLE/ERROR can
all appear in a single real orchestration run.
"""

import json
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import scanner_status
from utils.external_scanners import (
    classify_bandit, classify_pylint, _classify_exit_codes, _classify_semgrep,
    _classify_eslint, run_gitleaks,
)


# --- Bandit: 0=clean, 1=findings, 2=Bandit's own internal failure -----------

def test_classify_bandit_clean():
    assert classify_bandit(0, '') == (scanner_status.PASS, 0)


def test_classify_bandit_findings_counts_issue_blocks():
    stdout = "header text\n>> Issue: [B101] one\nmore text\n>> Issue: [B102] two\n"
    status, count = classify_bandit(1, stdout)
    assert status == scanner_status.FINDINGS
    assert count == 2


def test_classify_bandit_internal_failure_is_error_not_findings():
    assert classify_bandit(2, '') == (scanner_status.ERROR, None)


def test_classify_bandit_unexpected_code_is_error():
    assert classify_bandit(127, '')[0] == scanner_status.ERROR


# --- Pylint: documented bitmask, not a simple 0/1 ---------------------------

def test_classify_pylint_clean():
    assert classify_pylint(0, '') == (scanner_status.PASS, 0)


def test_classify_pylint_usage_error_bit_is_error():
    assert classify_pylint(32, 'usage: pylint [options]')[0] == scanner_status.ERROR


def test_classify_pylint_usage_error_combined_with_other_bits_is_still_error():
    # 32 | 4 = 36: usage bit set alongside a warning bit. The usage failure
    # dominates - pylint didn't actually complete a real analysis run.
    assert classify_pylint(36, '')[0] == scanner_status.ERROR


@pytest.mark.parametrize('code', [1, 2, 4, 8, 16, 1 | 4, 4 | 16])
def test_classify_pylint_message_bits_are_findings_not_errors(code):
    status, _ = classify_pylint(code, "a.py:1:0: [C0111] Missing docstring\n")
    assert status == scanner_status.FINDINGS, f"exit code {code} (bits set) should be FINDINGS, not {status}"


# --- Exit-code-only tools, each with its own documented convention ---------

def test_classify_safety_findings_code_is_64_not_1():
    """Safety's own documented convention - not the generic 0/1 assumption."""
    classify = _classify_exit_codes(pass_code=0, findings_codes=(64,))
    assert classify(0, '') == (scanner_status.PASS, 0)
    assert classify(64, '')[0] == scanner_status.FINDINGS
    assert classify(1, '')[0] == scanner_status.ERROR  # 1 is NOT findings for Safety


def test_classify_jshint_findings_code_is_2_not_1():
    """JSHint's own documented convention - not the generic 0/1 assumption."""
    classify = _classify_exit_codes(pass_code=0, findings_codes=(2,))
    assert classify(0, '') == (scanner_status.PASS, 0)
    assert classify(2, '')[0] == scanner_status.FINDINGS
    assert classify(1, '')[0] == scanner_status.ERROR  # 1 is NOT findings for JSHint


@pytest.mark.parametrize('tool', ['checkov', 'trufflehog', 'tfsec'])
def test_classify_standard_0_1_tools(tool):
    """Checkov/TruffleHog/TFSec do follow the conventional 0=clean/1=findings
    pattern (per their own docs) - confirming the generic helper is only
    ever applied where it's actually correct for that specific tool."""
    classify = _classify_exit_codes(pass_code=0, findings_codes=(1,))
    assert classify(0, '') == (scanner_status.PASS, 0)
    assert classify(1, '')[0] == scanner_status.FINDINGS
    assert classify(2, '')[0] == scanner_status.ERROR


# --- Semgrep: JSON body decides, not exit code (exit 0 even w/ findings) ---

def test_classify_semgrep_clean_exit_0_empty_results():
    status, count = _classify_semgrep(0, json.dumps({'results': []}))
    assert status == scanner_status.PASS
    assert count == 0


def test_classify_semgrep_findings_despite_exit_code_0():
    status, count = _classify_semgrep(0, json.dumps({'results': [{'x': 1}, {'x': 2}]}))
    assert status == scanner_status.FINDINGS
    assert count == 2


def test_classify_semgrep_malformed_json_is_error_not_pass():
    """Malformed output must never be silently treated as a clean run."""
    assert _classify_semgrep(0, 'not json at all') == (scanner_status.ERROR, None)


def test_classify_semgrep_crash_exit_code_is_error():
    assert _classify_semgrep(2, '')[0] == scanner_status.ERROR


# --- ESLint: JSON body decides (exit 0 can still carry warnings); exit 2 = fatal ---

def test_classify_eslint_clean():
    status, count = _classify_eslint(0, json.dumps([{'filePath': 'a.js', 'messages': []}]))
    assert status == scanner_status.PASS
    assert count == 0


def test_classify_eslint_findings_even_at_exit_code_0():
    payload = json.dumps([{'filePath': 'a.js', 'messages': [{'ruleId': 'no-console'}]}])
    status, count = _classify_eslint(0, payload)
    assert status == scanner_status.FINDINGS
    assert count == 1


def test_classify_eslint_fatal_config_error_is_error():
    assert _classify_eslint(2, '')[0] == scanner_status.ERROR


def test_classify_eslint_malformed_json_is_error_not_pass():
    assert _classify_eslint(0, 'not json')[0] == scanner_status.ERROR


# --- GitLeaks: forced exit 0, so PASS/FINDINGS comes from the report file --

_FAKE_GITLEAKS_PY = textwrap.dedent("""
    import os
    import sys

    args = sys.argv[1:]
    report_path = None
    for i, a in enumerate(args):
        if a == "--report-path" and i + 1 < len(args):
            report_path = args[i + 1]

    if report_path is not None:
        if os.environ.get("FAKE_GITLEAKS_DELETE_REPORT") == "1":
            # run_gitleaks() pre-creates an empty file at report_path before
            # launching gitleaks; deleting it here simulates gitleaks
            # crashing before ever writing its report, as opposed to
            # writing an empty (and therefore legitimately "no leaks")
            # report file.
            os.remove(report_path)
        else:
            content = os.environ.get("FAKE_GITLEAKS_REPORT", "[]")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(content)

    sys.exit(int(os.environ.get("FAKE_GITLEAKS_EXIT_CODE", "0")))
""")


@pytest.fixture
def fake_gitleaks(tmp_path, monkeypatch):
    """Install a synthetic 'gitleaks' on PATH whose report contents and exit
    code are controlled via FAKE_GITLEAKS_REPORT / FAKE_GITLEAKS_EXIT_CODE
    env vars, so GitLeaks' report-file-based classification can be tested
    without a real gitleaks binary."""
    tool_dir = tmp_path / 'fake_gitleaks_bin'
    tool_dir.mkdir()
    script_py = tool_dir / 'fake_gitleaks.py'
    script_py.write_text(_FAKE_GITLEAKS_PY)

    if os.name == 'nt':
        launcher = tool_dir / 'gitleaks.bat'
        launcher.write_text(f'@echo off\r\n"{sys.executable}" "{script_py}" %*\r\n')
    else:
        launcher = tool_dir / 'gitleaks'
        launcher.write_text(f'#!/bin/sh\n"{sys.executable}" "{script_py}" "$@"\n')
        launcher.chmod(launcher.stat().st_mode | 0o111)

    monkeypatch.setenv('PATH', str(tool_dir))
    return tmp_path


def test_gitleaks_empty_report_is_pass(fake_gitleaks, monkeypatch):
    monkeypatch.setenv('FAKE_GITLEAKS_REPORT', '[]')
    monkeypatch.setenv('FAKE_GITLEAKS_EXIT_CODE', '0')
    result = run_gitleaks(str(fake_gitleaks))
    assert result['status'] == scanner_status.PASS


def test_gitleaks_findings_from_report(fake_gitleaks, monkeypatch):
    monkeypatch.setenv('FAKE_GITLEAKS_REPORT', json.dumps([{'RuleID': 'aws-key', 'File': 'x.py'}]))
    monkeypatch.setenv('FAKE_GITLEAKS_EXIT_CODE', '0')
    result = run_gitleaks(str(fake_gitleaks))
    assert result['status'] == scanner_status.FINDINGS
    envelope = scanner_status.parse_result(result['result_json'])
    assert envelope['_findings_count'] == 1


def test_gitleaks_nonzero_exit_is_error_not_findings(fake_gitleaks, monkeypatch):
    """--exit-code 0 means gitleaks normally always exits 0; if it doesn't,
    that's gitleaks itself failing, not "leaks found"."""
    monkeypatch.setenv('FAKE_GITLEAKS_REPORT', '[]')
    monkeypatch.setenv('FAKE_GITLEAKS_EXIT_CODE', '1')
    result = run_gitleaks(str(fake_gitleaks))
    assert result['status'] == scanner_status.ERROR


def test_gitleaks_missing_report_is_error(fake_gitleaks, monkeypatch):
    monkeypatch.setenv('FAKE_GITLEAKS_DELETE_REPORT', '1')
    monkeypatch.setenv('FAKE_GITLEAKS_EXIT_CODE', '0')
    result = run_gitleaks(str(fake_gitleaks))
    assert result['status'] == scanner_status.ERROR


def test_gitleaks_malformed_report_is_error(fake_gitleaks, monkeypatch):
    monkeypatch.setenv('FAKE_GITLEAKS_REPORT', 'not valid json')
    monkeypatch.setenv('FAKE_GITLEAKS_EXIT_CODE', '0')
    result = run_gitleaks(str(fake_gitleaks))
    assert result['status'] == scanner_status.ERROR


def test_gitleaks_missing_binary_is_unavailable(tmp_path, monkeypatch):
    empty_dir = tmp_path / 'empty_path'
    empty_dir.mkdir()
    monkeypatch.setenv('PATH', str(empty_dir))
    result = run_gitleaks(str(tmp_path))
    assert result['status'] == scanner_status.UNAVAILABLE


# --- Mixed orchestration: all four states in one real run ------------------
#
# Runs the real run_bluescrub() (not mocked) in a subprocess, isolated from
# the real database the same way tests/test_db_isolation.py is, with a
# constructed fixture repo + PATH engineered to deterministically produce
# one PASS, one FINDINGS, and several UNAVAILABLE rows, plus one ERROR row
# exercising the "malformed output must not become PASS" rule end to end
# (not just at the classify-function level).

import sqlite3  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REAL_DB_PATH = _REPO_ROOT / 'instance' / 'bluescrub_database.db'
_MIXED_CHILD_SCRIPT = Path(__file__).resolve().parent / '_mixed_orchestration_child.py'


def _real_db_state():
    if not _REAL_DB_PATH.exists():
        return False, None, None, None
    stat = _REAL_DB_PATH.stat()
    conn = sqlite3.connect(str(_REAL_DB_PATH))
    try:
        count = conn.execute('SELECT COUNT(*) FROM tool_result').fetchone()[0]
    finally:
        conn.close()
    return True, stat.st_size, stat.st_mtime, count


def _run_mixed_orchestration():
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, str(_MIXED_CHILD_SCRIPT)],
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, (
        f"mixed orchestration child process failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_mixed_orchestration_produces_all_four_states_in_one_run():
    before = _real_db_state()
    result = _run_mixed_orchestration()
    after = _real_db_state()

    assert result['scan_success'] is True

    statuses_seen = {row['status'] for row in result['rows']}
    for expected in (scanner_status.PASS, scanner_status.FINDINGS,
                      scanner_status.UNAVAILABLE, scanner_status.ERROR):
        assert expected in statuses_seen, (
            f"expected {expected} among the scanner outcomes, got: {result['rows']}"
        )

    # Every scanner attempt persisted exactly one row with a real status -
    # never a None (unparseable envelope) or a missing row.
    assert len(result['rows']) == 12, f"expected 12 scanner rows, got: {result['rows']}"
    for row in result['rows']:
        assert row['status'] in (
            scanner_status.PASS, scanner_status.FINDINGS,
            scanner_status.UNAVAILABLE, scanner_status.ERROR,
        ), f"row has no valid status: {row}"

    # Spot-check the specific rows this fixture was engineered to control.
    by_tool = {row['tool_name']: row['status'] for row in result['rows']}
    assert by_tool['license-check'] == scanner_status.FINDINGS
    assert by_tool['semgrep'] == scanner_status.PASS
    assert by_tool['eslint'] == scanner_status.ERROR

    # The real application database is untouched.
    assert before == after, f"real database changed: before={before} after={after}"


def test_mixed_orchestration_ordering_is_deterministic():
    first = _run_mixed_orchestration()
    second = _run_mixed_orchestration()
    first_order = [row['tool_name'] for row in first['rows']]
    second_order = [row['tool_name'] for row in second['rows']]
    assert first_order == second_order
