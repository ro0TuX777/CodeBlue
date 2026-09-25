"""
Regression test for BlueScrub test/production database isolation.

app.py used to set app.config['SQLALCHEMY_DATABASE_URI'] unconditionally
after loading config.py's environment-specific config, which meant
TestingConfig's in-memory database was never actually used -- any code
path that writes to the database (like run_bluescrub()) wrote into the
real instance/bluescrub_database.db regardless of FLASK_ENV.

This test exercises the real run_bluescrub() path (not mocked, unlike
tests/test_smoke.py) with FLASK_ENV=testing set *before* app.py is
imported, in a subprocess, so config.get_config() is genuinely
responsible for selecting the database -- proving the fix is a
configuration fix, not a test-only monkeypatch.
"""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_DB_PATH = REPO_ROOT / 'instance' / 'bluescrub_database.db'
CHILD_SCRIPT = Path(__file__).resolve().parent / '_isolation_child.py'


def _real_db_state():
    """(exists, size, mtime, tool_result row count) for the real app database."""
    if not REAL_DB_PATH.exists():
        return False, None, None, None
    stat = REAL_DB_PATH.stat()
    conn = sqlite3.connect(str(REAL_DB_PATH))
    try:
        count = conn.execute('SELECT COUNT(*) FROM tool_result').fetchone()[0]
    finally:
        conn.close()
    return True, stat.st_size, stat.st_mtime, count


def _run_isolated_scan():
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
        f"isolation child process failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize('run_number', [1, 2, 3])
def test_bluescrub_scan_does_not_touch_real_database(run_number):
    """Run the real scan/DB-write path under testing config and prove the
    normal application database is untouched, deterministically across
    repeated runs."""
    before = _real_db_state()

    result = _run_isolated_scan()

    after = _real_db_state()

    # Testing configuration was genuinely active (config-driven, not a
    # post-import monkeypatch).
    assert result['testing_flag'] is True
    assert result['db_uri'] == 'sqlite:///:memory:'

    # The test database differs from the normal application database.
    assert result['db_uri'] != 'sqlite:///bluescrub_database.db'

    # Scanner execution actually ran and wrote into the (isolated) test database.
    assert result['scan_success'] is True
    assert result['tool_result_count'] >= 1

    # The real application database file and row count are unchanged.
    assert before == after, f"real database changed: before={before} after={after}"
