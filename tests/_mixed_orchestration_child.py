"""
Helper process for test_scanner_classification.py's mixed-outcome test.

Builds a fixture repo + a small synthetic PATH so a single run_bluescrub()
call deterministically produces all four scanner_status states in one run:

  - license-check -> FINDINGS  (a root LICENSE file declaring GPL)
  - semgrep       -> PASS      (synthetic 'semgrep' prints {"results": []}, exit 0)
  - eslint        -> ERROR     (synthetic 'eslint' prints malformed JSON, exit 0 -
                                 exercises the malformed-output-is-not-PASS rule)
  - everything else not explicitly installed (bandit, pylint, osv-scanner,
    safety, jshint, trufflehog, tfsec, gitleaks) -> UNAVAILABLE on a host
    that simply doesn't have them (e.g. this repo's Windows dev host).

On a host where every scanner actually is installed (e.g. inside the
CodeBlue Docker image - that's the point of Gate 4), none of the above
would naturally be missing, so 'checkov' specifically is forced
UNAVAILABLE regardless of platform: if a real checkov is found on PATH, its
binary is renamed aside for the duration of the run and restored
afterward, guaranteeing this test's determinism doesn't depend on which
scanners happen to be provisioned on whatever host runs it.

Runs in a subprocess with FLASK_ENV=testing, same isolation pattern as
tests/_isolation_child.py, so it never touches the real database.
"""
import json
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# Force 'checkov' UNAVAILABLE regardless of platform/provisioning (see
# module docstring). Located and renamed *before* PATH is touched below, so
# this uses whatever the real ambient PATH resolves it to.
_checkov_real_path = shutil.which('checkov')
_checkov_hidden_path = None
if _checkov_real_path is not None:
    _checkov_hidden_path = _checkov_real_path + '.hidden_for_gate4_test'
    os.rename(_checkov_real_path, _checkov_hidden_path)

# --- Build a synthetic PATH containing only 'semgrep' and 'eslint' ---------
tool_dir = os.path.join(REPO_ROOT, 'tests', '_mixed_orchestration_tools')
if os.path.exists(tool_dir):
    shutil.rmtree(tool_dir)
os.makedirs(tool_dir)

if os.name == 'nt':
    semgrep_path = os.path.join(tool_dir, 'semgrep.bat')
    with open(semgrep_path, 'w') as f:
        f.write('@echo off\r\necho {"results": []}\r\n')

    eslint_path = os.path.join(tool_dir, 'eslint.bat')
    with open(eslint_path, 'w') as f:
        f.write('@echo off\r\necho this is not valid json\r\n')
else:
    semgrep_path = os.path.join(tool_dir, 'semgrep')
    with open(semgrep_path, 'w') as f:
        f.write('#!/bin/sh\necho \'{"results": []}\'\n')
    os.chmod(semgrep_path, 0o755)

    eslint_path = os.path.join(tool_dir, 'eslint')
    with open(eslint_path, 'w') as f:
        f.write('#!/bin/sh\necho "this is not valid json"\n')
    os.chmod(eslint_path, 0o755)

# Prepend (not replace) - real tools like git.exe (which app.py's import
# chain needs) must stay reachable; our fake semgrep/eslint just need to
# resolve first, and bandit/pylint/etc. genuinely aren't anywhere on the
# real PATH either, so they still correctly come back UNAVAILABLE.
os.environ['PATH'] = tool_dir + os.pathsep + os.environ.get('PATH', '')

os.environ['FLASK_ENV'] = 'testing'
import app as appmod  # noqa: E402
from utils import scanner_status  # noqa: E402

target_dir = os.path.join(REPO_ROOT, 'tests', '_mixed_orchestration_fixture_repo')
if os.path.exists(target_dir):
    shutil.rmtree(target_dir)
os.makedirs(target_dir)
with open(os.path.join(target_dir, 'vuln.py'), 'w') as f:
    f.write("import os\nos.system('echo hi')\n")
with open(os.path.join(target_dir, 'LICENSE'), 'w') as f:
    f.write(
        "GNU GENERAL PUBLIC LICENSE\n"
        "Version 3, 29 June 2007\n\n"
        "This program is free software: you can redistribute it and/or modify\n"
        "it under the terms of the GNU General Public License as published by\n"
        "the Free Software Foundation.\n"
    )

repo_name = 'mixed_orchestration_fixture_repo'
result = {}

try:
    with appmod.app.app_context():
        appmod.db.create_all()

        scan_result = appmod.run_bluescrub(target_dir, repo_name)
        result['scan_success'] = scan_result.get('success')

        rows = appmod.ToolResult.query.filter_by(repo_name=repo_name).order_by(appmod.ToolResult.id).all()
        result['rows'] = []
        for r in rows:
            envelope = scanner_status.parse_result(r.result)
            result['rows'].append({
                'id': r.id,
                'tool_name': r.tool_name,
                'status': envelope['_status'] if envelope else None,
            })
finally:
    shutil.rmtree(target_dir, ignore_errors=True)
    shutil.rmtree(tool_dir, ignore_errors=True)
    if _checkov_hidden_path is not None and _checkov_real_path is not None:
        os.rename(_checkov_hidden_path, _checkov_real_path)

print(json.dumps(result))
