"""
Orchestration for external CLI security tools whose ToolResult rows exist in
the historical database (safety, semgrep, checkov, eslint, jshint,
trufflehog, gitleaks, tfsec) but which nothing in the current app.py actually
invokes anymore - only Bandit and Pylint are wired up today.

This module restores that orchestration using the same graceful-degradation
contract Bandit/Pylint already use: a missing binary or a timeout produces a
logged, non-fatal message instead of crashing the scan.

Scope note: each tool's raw output is captured as-is (JSON where the tool
supports it reliably, plain text otherwise) and stored verbatim in
ToolResult.result, matching what the historical rows in the database already
look like. None of these are parsed into the structured per-finding view
`/security_issues` uses for Bandit/Pylint/OSV-Scanner/license-check - that
would require verifying each tool's actual output schema against a real
installed binary, which wasn't possible in the environment this was written
in. Treat the exact CLI flags below as best-effort and confirm them once
these binaries are actually installed.

Execution boundary
-------------------
Every function here takes the target repository's directory explicitly and
runs its tool with cwd=<that directory>, instead of relying on the caller
having os.chdir()'d into it. That matters for more than tidiness: on
Windows, both shutil.which() and CreateProcess's own executable search check
the *process's* current directory before PATH. If BlueScrub ever chdir'd
into a repository it's scanning - untrusted content by definition - a repo
that ships e.g. `eslint.exe`/`bandit.exe`/`gitleaks.cmd` in its root would
get resolved and executed *instead of* the real installed tool. Keeping the
process's own cwd fixed at BlueScrub's own directory and passing cwd= to
each subprocess call is what keeps "which tool runs" independent of what the
scanned repository contains (see app.py's run_bluescrub()).

Result classification
----------------------
Every run_xxx() below resolves to exactly one of scanner_status.{PASS,
FINDINGS, UNAVAILABLE, ERROR} (see utils/scanner_status.py for the shared
envelope every scanner's result gets encoded into). A generic "exit code 0
or 1 both mean success" rule does not hold across this tool set - see each
_classify_*() function's docstring for the specific, tool-by-tool evidence
behind its exit-code/output interpretation.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile

from utils import scanner_status

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 300

# Characters with special meaning to cmd.exe's own command-line parser.
# .cmd/.bat files can't be exec'd directly on Windows (CreateProcess needs a
# real PE image) so they always go through cmd.exe as an interpreter, and
# subprocess's own argument quoting (list2cmdline) only quotes an argument
# that contains whitespace - it has no reason to know about cmd.exe
# metacharacters. An argument with one of these characters and no whitespace
# would reach cmd.exe's tokenizer unquoted and be interpreted as shell
# syntax rather than data. Every argument passed to a scanner today is a
# static literal (see each run_xxx() below), so this never actually fires -
# it exists so that adding a repository-derived argument later fails closed
# instead of silently becoming a shell injection.
_SHELL_UNSAFE_CHARS = set('&|<>^%!"()\n\r')


class UnsafeArgumentError(ValueError):
    """An argument bound for a cmd.exe-launched tool contains a character
    that could let it break out of its own argument position."""


def _find_command_processor():
    """Absolute path to the trusted Windows command processor (cmd.exe)."""
    comspec = os.environ.get('ComSpec')
    if comspec and os.path.isfile(comspec):
        return comspec
    return shutil.which('cmd.exe') or shutil.which('cmd')


def _find_powershell():
    return shutil.which('powershell') or shutil.which('pwsh')


def _prepare_launch(resolved: str, args: list) -> list:
    """
    Build the argv to hand to subprocess.run() (always with shell=False) for
    a resolved, absolute tool path, honoring whatever interpreter that
    file's extension actually requires on Windows.

    Native executables (and everything on non-Windows platforms) need
    nothing special: [resolved] + args, run directly. .cmd/.bat and .ps1
    each need a real interpreter in front of them - and a different one,
    since PowerShell invocation semantics aren't CMD's (requirement: handle
    .ps1 deliberately, not as a synonym for .bat). Raises UnsafeArgumentError
    or FileNotFoundError instead of ever falling back to shell=True.
    """
    lowered = resolved.lower()

    if os.name != 'nt' or not lowered.endswith(('.cmd', '.bat', '.ps1')):
        return [resolved] + args

    for arg in args:
        if any(ch in _SHELL_UNSAFE_CHARS for ch in arg):
            raise UnsafeArgumentError(
                f"argument {arg!r} contains a character reserved by the "
                "Windows command processor; refusing to launch a shell-"
                "interpreted tool with it"
            )

    if lowered.endswith('.ps1'):
        powershell = _find_powershell()
        if powershell is None:
            raise FileNotFoundError('powershell.exe/pwsh not found on PATH to run a .ps1 tool')
        # PowerShell parses its own argv the normal way - there's no second
        # shell layer re-tokenizing the command line the way cmd.exe does,
        # so the args list is passed straight through.
        return [powershell, '-NoProfile', '-NonInteractive',
                '-ExecutionPolicy', 'Bypass', '-File', resolved] + args

    # .cmd / .bat: launched via the trusted, absolute-path cmd.exe as an
    # explicit interpreter (not subprocess's shell=True, which would
    # re-derive comspec itself and hand it the *entire* re-joined command
    # line to parse). Every argument was just checked above for cmd.exe
    # metacharacters, so there's nothing left for its tokenizer to act on.
    comspec = _find_command_processor()
    if comspec is None:
        raise FileNotFoundError('cmd.exe not found to run a .cmd/.bat tool')
    return [comspec, '/c', resolved] + args


# --- Per-tool result classification -----------------------------------------
#
# Each classify(returncode, stdout) -> (status, findings_count) function
# below encodes one tool's *documented* exit-code/output convention. None of
# these guess: where a tool's own docs don't establish a code's meaning
# clearly enough to classify safely, this errs toward ERROR rather than
# guessing PASS or FINDINGS (see individual docstrings for the source of
# each convention).

def _classify_exit_codes(pass_code=0, findings_codes=(1,)):
    """
    Build a classify() for tools whose exit code alone distinguishes clean
    from findings, with no reliable per-finding count available without
    re-parsing tool-specific output. `findings_codes` is a tuple because it
    is not universally {1} - see call sites below (Safety's 64, JSHint's 2).
    """
    def classify(returncode, stdout):
        if returncode == pass_code:
            return scanner_status.PASS, 0
        if returncode in findings_codes:
            return scanner_status.FINDINGS, None
        return scanner_status.ERROR, None
    return classify


def classify_bandit(returncode, stdout):
    """
    Bandit (run directly from app.py, not through run_cli_tool - it has no
    resolution step to share since app.py invokes it by bare name). Bandit's
    own documented exit codes: 0 = no issues found, 1 = issues found, 2 =
    Bandit itself failed (e.g. couldn't parse a file) - a tool failure, not
    "no issues". Findings are counted from Bandit's plain-text output (no
    -f json flag is passed - see app.py), where each finding starts a
    ">> Issue:" block.
    """
    if returncode == 0:
        return scanner_status.PASS, 0
    if returncode == 1:
        return scanner_status.FINDINGS, stdout.count('>> Issue:') or None
    return scanner_status.ERROR, None


_PYLINT_USAGE_ERROR_BIT = 32  # pylint's documented "usage error" exit bit


def classify_pylint(returncode, stdout):
    """
    Pylint (run directly from app.py). Pylint's exit code is a documented
    bitmask, not a simple 0/1: bit 1 = fatal, 2 = error, 4 = warning,
    8 = refactor, 16 = convention, 32 = usage error. 0 = no messages at all.

    Bits 1/2/4/8/16 all mean "pylint ran and is reporting messages about the
    analyzed code" - i.e. findings, regardless of which specific bits are
    set. Bit 32 (usage error) means pylint itself couldn't run as invoked
    (bad arguments/config) - a tool failure, kept separate from findings
    even if it happens to be combined with other bits.
    """
    if returncode == 0:
        return scanner_status.PASS, 0
    if returncode & _PYLINT_USAGE_ERROR_BIT:
        return scanner_status.ERROR, None
    # Best-effort per-line count of pylint's "file:line:col: message" text
    # format (--output-format=text, per app.py's invocation).
    count = sum(1 for line in stdout.splitlines() if len(line.split(':', 3)) >= 4 and '[' in line and ']' in line)
    return scanner_status.FINDINGS, count or None


def _classify_semgrep(returncode, stdout):
    """
    Semgrep, as invoked here (`semgrep scan --config auto --json .`, no
    `--error` flag), exits 0 whether or not it found anything - `--error` is
    what would make findings produce a non-zero exit, and this invocation
    deliberately doesn't pass it (Gate 1B: don't change invocation flags
    just to make exit-code interpretation easier). So PASS vs FINDINGS is
    read from the JSON body's `results` array instead of the exit code;
    exit codes outside {0, 1} and unparseable/malformed JSON both mean the
    run itself is untrustworthy, not "no findings" - hence ERROR, not PASS.
    """
    if returncode not in (0, 1):
        return scanner_status.ERROR, None
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return scanner_status.ERROR, None
    results = data.get('results') if isinstance(data, dict) else None
    if not isinstance(results, list):
        return scanner_status.ERROR, None
    return (scanner_status.FINDINGS, len(results)) if results else (scanner_status.PASS, 0)


def _classify_eslint(returncode, stdout):
    """
    ESLint exit 0 can still carry warning-level messages (exit 1 only
    reflects error-level ones by default), so PASS vs FINDINGS is read from
    the JSON body (`-f json` is already passed) rather than trusting the
    exit code to mean "clean". Exit 2 is ESLint's own documented fatal/
    config-error code (e.g. a broken .eslintrc) - a tool failure, not zero
    findings.
    """
    if returncode == 2:
        return scanner_status.ERROR, None
    if returncode not in (0, 1):
        return scanner_status.ERROR, None
    try:
        data = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError:
        return scanner_status.ERROR, None
    if not isinstance(data, list):
        return scanner_status.ERROR, None
    count = sum(len(entry.get('messages', [])) for entry in data if isinstance(entry, dict))
    return (scanner_status.FINDINGS, count) if count else (scanner_status.PASS, 0)


def run_cli_tool(tool_name: str, command: list, cwd: str, classify, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """
    Run an external CLI tool, capture its output, and classify the outcome
    into exactly one of scanner_status.{PASS, FINDINGS, UNAVAILABLE, ERROR}.

    `classify(returncode, stdout) -> (status, findings_count)` carries the
    tool-specific exit-code/output semantics the caller already knows (see
    the run_xxx() functions below and their _classify_*() helpers); this
    function only owns resolution, launching, and turning whatever happens -
    including a missing binary, an unsafe argument, or a timeout - into a
    ToolResult-ready envelope. It never raises.

    Returns {'status': str, 'result_json': str, 'display_output': str}.
    `result_json` is what to store in ToolResult.result (the scanner_status
    envelope); `display_output` is human-readable text for the scan's HTML
    report.
    """
    resolved = shutil.which(command[0])
    if resolved is None:
        message = f"{tool_name} is not installed or not on PATH. Skipped.\n"
        logger.warning(message.strip())
        return {
            'status': scanner_status.UNAVAILABLE,
            'result_json': scanner_status.build_result(scanner_status.UNAVAILABLE, message.strip()),
            'display_output': message,
        }

    try:
        argv = _prepare_launch(resolved, command[1:])
    except (UnsafeArgumentError, FileNotFoundError) as e:
        message = f"{tool_name}: refusing to run - {e}\n"
        logger.error(message.strip())
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(scanner_status.ERROR, str(e)),
            'display_output': message,
        }

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, cwd=cwd)
    except subprocess.TimeoutExpired:
        message = f"{tool_name} timed out after {timeout} seconds\n"
        logger.error(message.strip())
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(scanner_status.ERROR, f'timeout after {timeout}s'),
            'display_output': message,
        }
    except Exception as e:
        message = f"Error running {tool_name}: {str(e)}\n"
        logger.error(message.strip())
        logger.exception(f"{tool_name} error details:")
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(scanner_status.ERROR, str(e)),
            'display_output': message,
        }

    output = result.stdout
    if result.stderr and result.returncode not in (0, 1):
        output += f"\n[stderr] {result.stderr}"

    status, findings_count = classify(result.returncode, result.stdout)
    summary = f"{tool_name}: {status}"
    if findings_count:
        summary += f" ({findings_count} finding(s))"
    return {
        'status': status,
        'result_json': scanner_status.build_result(
            status, summary, exit_code=result.returncode, findings_count=findings_count, output=output,
        ),
        'display_output': output,
    }


def run_safety(directory: str) -> dict:
    """
    Python dependency vulnerability check. Requires a requirements.txt in
    the scanned repo; with none present there is nothing to check, so this
    is PASS (matching the pre-existing behavior), not UNAVAILABLE - the
    *tool* is available, the target condition just isn't met.

    Exit codes (safety-cli's own documented convention, not the generic
    0/1 assumption): 0 = no known vulnerabilities, 64 = vulnerabilities
    found. Other non-zero codes (e.g. 65 = invalid API key, 66 = DB load
    failure) are execution problems, not findings, so they classify as
    ERROR rather than being folded into "findings".
    """
    if not os.path.exists(os.path.join(directory, 'requirements.txt')):
        message = "No requirements.txt found; Safety check skipped.\n"
        return {
            'status': scanner_status.PASS,
            'result_json': scanner_status.build_result(scanner_status.PASS, message.strip(), findings_count=0),
            'display_output': message,
        }
    return run_cli_tool(
        'Safety', ['safety', 'check', '-r', 'requirements.txt', '--json'], cwd=directory,
        classify=_classify_exit_codes(pass_code=0, findings_codes=(64,)),
    )


def run_semgrep(directory: str) -> dict:
    """Multi-language SAST using Semgrep's auto rule config."""
    return run_cli_tool(
        'Semgrep', ['semgrep', 'scan', '--config', 'auto', '--json', '.'], cwd=directory,
        classify=_classify_semgrep,
    )


def run_checkov(directory: str) -> dict:
    """
    IaC misconfiguration scan (Terraform, CloudFormation, Kubernetes, etc.).
    Checkov's documented default (no --soft-fail passed): exit 0 = no
    failed checks, exit 1 = failed checks found.
    """
    return run_cli_tool(
        'Checkov', ['checkov', '-d', '.', '-o', 'json'], cwd=directory,
        classify=_classify_exit_codes(pass_code=0, findings_codes=(1,)),
    )


def run_eslint(directory: str) -> dict:
    """JS/TS linting, including security-relevant rules if the repo's own config enables them."""
    return run_cli_tool('ESLint', ['eslint', '.', '-f', 'json'], cwd=directory, classify=_classify_eslint)


def run_jshint(directory: str) -> dict:
    """
    JS linting. No reliable built-in JSON reporter, so this captures plain
    text and classifies by exit code alone: JSHint's own documented
    convention is exit 0 = clean, exit 2 = warnings/errors found (not 1 -
    this is JSHint-specific, unlike most of the rest of this tool set).
    """
    return run_cli_tool(
        'JSHint', ['jshint', '.'], cwd=directory,
        classify=_classify_exit_codes(pass_code=0, findings_codes=(2,)),
    )


def run_trufflehog(directory: str) -> dict:
    """
    Secret detection (TruffleHog v2, matching the version pinned in
    requirements.txt). Documented convention: exit 0 = no secrets found,
    exit 1 = secrets found.

    --regex is required, not optional: confirmed against a real trufflehog
    2.2.1 install, without it every scan reports 0 findings regardless of
    content - even an unambiguous AWS access key in a committed file - since
    default detection is Shannon-entropy-only and doesn't reliably flag
    common credential patterns. With --regex, the same fixture is correctly
    flagged.

    Known unresolved limitation (Gate 4): TruffleHog v2's positional
    argument is a git_url it clones, not an arbitrary directory - `.` only
    works when `directory` already has a .git history (true for a GitHub
    URL scan, since app.py clones those). For a local/network-path scan
    (shutil.copytree(), no .git), trufflehog crashes with an unhandled
    GitCommandError and returns exit 1 - which the exit-code classifier
    above currently reads as FINDINGS, not the tool failure it actually is.
    Not fixed here: doing so changes what TruffleHog actually scans for
    non-git content (init a throwaway repo first? skip it entirely?), which
    is a real design decision, not a one-line correction.
    """
    return run_cli_tool(
        'TruffleHog', ['trufflehog', '--json', '--regex', '.'], cwd=directory,
        classify=_classify_exit_codes(pass_code=0, findings_codes=(1,)),
    )


def run_tfsec(directory: str) -> dict:
    """
    Terraform security scan. Documented default (no --soft-fail passed):
    exit 0 = no issues, exit 1 = issues found.
    """
    return run_cli_tool(
        'TFSec', ['tfsec', '.', '--format', 'json', '--no-color'], cwd=directory,
        classify=_classify_exit_codes(pass_code=0, findings_codes=(1,)),
    )


def run_gitleaks(directory: str) -> dict:
    """
    Secret detection across the repo.

    The invocation passes --exit-code 0, which makes gitleaks always exit 0
    whether or not it found leaks - a deliberate pre-existing choice (see
    the --report-path plumbing below), not a bug to fix here. That means
    PASS vs FINDINGS has to come from the report file's contents, not the
    exit code; a non-zero exit here can only mean gitleaks itself failed
    (bad arguments, internal crash), which is why that's classified as
    ERROR and kept fully separate from "ran fine, found nothing".
    """
    resolved = shutil.which('gitleaks')
    if resolved is None:
        message = "gitleaks is not installed or not on PATH. Skipped.\n"
        logger.warning(message.strip())
        return {
            'status': scanner_status.UNAVAILABLE,
            'result_json': scanner_status.build_result(scanner_status.UNAVAILABLE, message.strip()),
            'display_output': message,
        }

    with tempfile.NamedTemporaryFile(mode='r', suffix='.json', delete=False) as tmp:
        report_path = tmp.name

    try:
        argv = _prepare_launch(resolved, [
            'detect', '--source', '.', '--no-git',
            '--report-format', 'json', '--report-path', report_path, '--exit-code', '0',
        ])
    except (UnsafeArgumentError, FileNotFoundError) as e:
        message = f"GitLeaks: refusing to run - {e}\n"
        logger.error(message.strip())
        try:
            os.unlink(report_path)
        except OSError:
            pass
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(scanner_status.ERROR, str(e)),
            'display_output': message,
        }

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT_SECONDS,
                                 shell=False, cwd=directory)
    except subprocess.TimeoutExpired:
        message = f"GitLeaks timed out after {DEFAULT_TIMEOUT_SECONDS} seconds\n"
        logger.error(message.strip())
        try:
            os.unlink(report_path)
        except OSError:
            pass
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(
                scanner_status.ERROR, f'timeout after {DEFAULT_TIMEOUT_SECONDS}s'),
            'display_output': message,
        }
    except Exception as e:
        message = f"Error running GitLeaks: {str(e)}\n"
        logger.error(message.strip())
        logger.exception("GitLeaks error details:")
        try:
            os.unlink(report_path)
        except OSError:
            pass
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(scanner_status.ERROR, str(e)),
            'display_output': message,
        }

    if result.returncode != 0:
        message = f"GitLeaks exited {result.returncode} (execution failure, not findings): {result.stderr.strip()}\n"
        logger.error(message.strip())
        try:
            os.unlink(report_path)
        except OSError:
            pass
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(
                scanner_status.ERROR, message.strip(), exit_code=result.returncode),
            'display_output': message,
        }

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_text = f.read()
    except OSError as e:
        message = f"GitLeaks produced no readable report file: {e}\n"
        logger.error(message.strip())
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(
                scanner_status.ERROR, message.strip(), exit_code=result.returncode),
            'display_output': message,
        }
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    try:
        leaks = json.loads(report_text) if report_text.strip() else []
    except json.JSONDecodeError as e:
        message = f"GitLeaks report file was not valid JSON: {e}\n"
        logger.error(message.strip())
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(
                scanner_status.ERROR, message.strip(), exit_code=result.returncode, output=report_text),
            'display_output': report_text or message,
        }

    if not isinstance(leaks, list):
        message = "GitLeaks report file was valid JSON but not the expected findings list.\n"
        logger.error(message.strip())
        return {
            'status': scanner_status.ERROR,
            'result_json': scanner_status.build_result(
                scanner_status.ERROR, message.strip(), exit_code=result.returncode, output=report_text),
            'display_output': report_text or message,
        }

    status = scanner_status.FINDINGS if leaks else scanner_status.PASS
    summary = f"GitLeaks: {status} ({len(leaks)} finding(s))"
    return {
        'status': status,
        'result_json': scanner_status.build_result(
            status, summary, exit_code=result.returncode, findings_count=len(leaks),
            output=report_text, findings=leaks,
        ),
        'display_output': report_text or "GitLeaks: no leaks found.\n",
    }


# Tools that were historically run but aren't wired up here: rubocop, brakeman
# (Ruby), phpcs, psalm (PHP), swiftlint (Swift), oclint (Objective-C), clang
# (C/C++), golangci_lint, gosec (Go), dependency_check (superseded by
# OSV-Scanner). Each needs a separate language toolchain provisioned in the
# Docker image; see the conversation this module was introduced in for the
# tradeoffs.
SCANNERS = {
    'safety': run_safety,
    'semgrep': run_semgrep,
    'checkov': run_checkov,
    'eslint': run_eslint,
    'jshint': run_jshint,
    'trufflehog': run_trufflehog,
    'tfsec': run_tfsec,
    'gitleaks': run_gitleaks,
}
