"""
Helper process for test_scanner_orchestration.py.

Same rationale as tests/_isolation_child.py: runs run_bluescrub() for real,
in a separate process with FLASK_ENV=testing set before app.py is imported,
so it writes to an isolated in-memory database rather than the real
instance/bluescrub_database.db.
"""
import json
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import app as appmod  # noqa: E402

target_dir = os.path.join(REPO_ROOT, 'tests', '_orchestration_fixture_repo')
if os.path.exists(target_dir):
    shutil.rmtree(target_dir)
os.makedirs(target_dir)
with open(os.path.join(target_dir, 'vuln.py'), 'w') as f:
    f.write("import os\nos.system('echo hi')\n")

repo_name = 'orchestration_fixture_repo'
result = {}

try:
    with appmod.app.app_context():
        appmod.db.create_all()

        scan_result = appmod.run_bluescrub(target_dir, repo_name)
        result['scan_success'] = scan_result.get('success')

        rows = appmod.ToolResult.query.filter_by(repo_name=repo_name).order_by(appmod.ToolResult.id).all()
        result['rows'] = [
            {'id': r.id, 'tool_name': r.tool_name, 'result_prefix': r.result[:120]}
            for r in rows
        ]

        # Also exercise /security_issues for this repo - it's the main
        # consumer of ToolResult rows, and its ToolResult-parsing loop must
        # not crash regardless of which scanners were
        # available/unavailable/errored. extract_metrics_from_scan (called
        # inside run_bluescrub) already populated MetricsHistory, which
        # /security_issues requires to get past its own first check.
        #
        # templates/security_issues.html does not exist in this repo at all
        # (a separate, pre-existing bug, unrelated to ToolResult handling -
        # not this gate's scope), so the route always fails at the final
        # render_template() call with jinja2.TemplateNotFound - and with
        # TESTING=True, Flask's test client re-raises that instead of
        # turning it into a 500 response. That failure mode is expected and
        # orthogonal to what this test checks: that nothing *before* the
        # render call - i.e. the ToolResult JSON-parsing loop this gate
        # touched - raises some other, unexpected exception.
        import jinja2
        with appmod.app.test_client() as client:
            try:
                resp = client.get(f'/security_issues/{repo_name}')
                result['security_issues_status'] = resp.status_code
                result['security_issues_exception'] = None
            except jinja2.TemplateNotFound:
                result['security_issues_status'] = None
                result['security_issues_exception'] = 'TemplateNotFound (pre-existing, unrelated)'
finally:
    shutil.rmtree(target_dir, ignore_errors=True)

print(json.dumps(result))
