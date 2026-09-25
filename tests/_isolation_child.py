"""
Helper process for test_db_isolation.py.

Runs as a separate Python process (not imported inside the pytest process)
so FLASK_ENV=testing is read by config.get_config() at import time, the same
way a real deployment would pick TestingConfig -- rather than monkeypatching
app.config['SQLALCHEMY_DATABASE_URI'] after import, which is what the
existing smoke-test fixture does and which would hide the app.py override
bug this test guards against.
"""
import json
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import app as appmod  # noqa: E402

result = {
    'testing_flag': appmod.app.config['TESTING'],
    'db_uri': appmod.app.config['SQLALCHEMY_DATABASE_URI'],
}

target_dir = os.path.join(REPO_ROOT, 'tests', '_isolation_fixture_repo')
if os.path.exists(target_dir):
    shutil.rmtree(target_dir)
os.makedirs(target_dir)
with open(os.path.join(target_dir, 'vuln.py'), 'w') as f:
    f.write("import os\nos.system('echo hi')\n")

try:
    with appmod.app.app_context():
        appmod.db.create_all()
        scan_result = appmod.run_bluescrub(target_dir, 'isolation_fixture_repo')
        result['scan_success'] = scan_result.get('success')
        result['tool_result_count'] = appmod.ToolResult.query.count()
finally:
    shutil.rmtree(target_dir, ignore_errors=True)

print(json.dumps(result))
