"""
Minimal smoke tests for CodeBlue.

These are not a full regression suite -- they exist to catch the kind of
breakage a platform/environment change (e.g. the Linux/Docker migration)
tends to cause: modules that fail to import, routes that go missing, and
the couple of request flows that were fixed or touched most recently.
"""

import os
import shutil
from unittest.mock import patch

import pytest


@pytest.fixture
def client():
    """A Flask test client backed by a throwaway in-memory database."""
    import app as appmod

    appmod.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    appmod.app.config['TESTING'] = True
    with appmod.app.app_context():
        appmod.db.create_all()
    with appmod.app.test_client() as test_client:
        yield test_client


# --- Import checks ---------------------------------------------------------

def test_core_modules_import():
    """Every module the app depends on at startup should import cleanly.

    utils.url_checker and utils.data_handler are deliberately excluded:
    they're orphaned legacy scripts app.py never imports, and
    utils/url_checker.py currently can't even be imported (it references a
    function that doesn't exist in utils/data_handler.py).
    """
    import app  # noqa: F401
    import config  # noqa: F401
    import ci_integration  # noqa: F401
    from utils import (  # noqa: F401
        binary_analyzer,
        link_extractor,
        metrics_analyzer,
        repo_visualizer,
        security_posture,
        taint_analyzer,
        typesafe_triage,
    )


# --- Route registration ------------------------------------------------------

def test_expected_routes_are_registered():
    import app as appmod

    routes = {rule.rule for rule in appmod.app.url_map.iter_rules()}
    expected = {
        '/',
        '/scrape',
        '/review',
        '/scan_code',
        '/clone_repository',
        '/analyze-binary',
        '/setup-ghidra',
        '/setup-radare2',
        '/setup-capstone',
        '/security_issues/<repo_name>',
        '/dashboard',
        '/binary-analysis',
    }
    missing = expected - routes
    assert not missing, f"Expected routes missing from url_map: {missing}"
    assert len(routes) >= 30, f"Only {len(routes)} routes registered; expected at least 30"


# --- Golden-path requests ----------------------------------------------------

def test_index_page_loads(client):
    resp = client.get('/')
    assert resp.status_code == 200


def test_dashboard_overview_loads_with_no_data(client):
    resp = client.get('/dashboard')
    assert resp.status_code == 200


def test_scan_code_copies_local_path_and_scans_it(client, tmp_path):
    """Regression test: local/network paths must actually be scanned, not
    silently produce an empty-directory scan (the bug fixed this session)."""
    src = tmp_path / "sample_project"
    src.mkdir()
    (src / "vuln.py").write_text("import os\nos.system('echo hi')\n")

    import app as appmod

    fake_result = {
        'success': True,
        'output': 'ok',
        'high_severity_issues': 0,
        'medium_severity_issues': 0,
        'low_severity_issues': 0,
    }
    scan_dir = os.path.join('Untested', 'sample_project')
    try:
        with patch.object(appmod, 'run_bluescrub', return_value=fake_result) as mock_run:
            resp = client.post('/scan_code', data={'repo_to_scan': str(src)})

            assert resp.status_code == 200
            assert mock_run.called, "run_bluescrub was never called"
            scanned_dir = mock_run.call_args[0][0]
            assert os.path.isfile(os.path.join(scanned_dir, 'vuln.py')), (
                "The local project's contents were not copied into the scan directory"
            )
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


def test_scan_code_rejects_unreachable_path(client):
    """A path that isn't a URL and isn't visible on disk must fail loudly,
    not silently scan an empty directory."""
    bogus_path = os.path.join('nonexistent', 'definitely_missing_xyz')
    scan_dir = os.path.join('Untested', 'definitely_missing_xyz')
    try:
        resp = client.post('/scan_code', data={'repo_to_scan': bogus_path})
        assert resp.status_code == 200
        assert b'not a reachable local/network path' in resp.data
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)
