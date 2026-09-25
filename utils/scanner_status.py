"""
Shared vocabulary for classifying a scanner attempt into exactly one of four
states, and for encoding that classification into ToolResult.result without
a database schema change (ToolResult stays id/repo_name/tool_name/result/
timestamp - see app.py's ToolResult model).

Every scanner's own return-code/output semantics differ (see
utils/external_scanners.py, utils/dependency_scanner.py,
utils/license_analyzer.py, and app.py's run_bluescrub() for bandit/pylint),
so the *classification* logic lives next to each scanner's invocation code.
This module only defines the shared states and the one envelope shape every
scanner's result gets encoded into, so a consumer (e.g. /security_issues)
only has to learn one shape regardless of which scanner produced it.
"""

import json

PASS = 'PASS'
FINDINGS = 'FINDINGS'
UNAVAILABLE = 'UNAVAILABLE'
ERROR = 'ERROR'

_VALID_STATUSES = {PASS, FINDINGS, UNAVAILABLE, ERROR}


def build_result(status: str, message: str, *, exit_code=None, findings_count=None,
                  output: str = '', findings=None) -> str:
    """
    Encode one scanner attempt's outcome as the JSON string to store in
    ToolResult.result.

    Envelope shape is identical across every scanner:
      _status           PASS / FINDINGS / UNAVAILABLE / ERROR
      _exit_code        the process's exit code, or null (missing binary,
                         a Python-level exception/timeout, or a scanner with
                         no real exit code like license-check)
      _message          one-line human-readable summary
      _findings_count   int if known, else null (status isn't FINDINGS, or
                         the count genuinely couldn't be determined)
      _output           raw tool stdout/text, '' if none
      _findings         structured findings list for tools that already
                         produce one (osv-scanner, license-check), else null

    Every key is prefixed with an underscore so this envelope can never be
    confused with a tool's own JSON keys, including when a tool's raw JSON
    ends up nested under _output.
    """
    if status not in _VALID_STATUSES:
        raise ValueError(f"invalid scanner status: {status!r}")
    return json.dumps({
        '_status': status,
        '_exit_code': exit_code,
        '_message': message,
        '_findings_count': findings_count,
        '_output': output,
        '_findings': findings,
    })


def parse_result(raw: str):
    """
    Decode a ToolResult.result string back into its envelope dict, or None
    if `raw` isn't one of this module's envelopes (e.g. a row written before
    this module existed). Callers should fall back to their own legacy
    parsing when this returns None, rather than assuming every row is
    already in the new shape.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict) or data.get('_status') not in _VALID_STATUSES:
        return None
    return data
