"""
Adversarial tests for the external-scanner execution boundary
(utils/external_scanners.py, and the way app.py's run_bluescrub() invokes
Bandit/Pylint).

Threat model: BlueScrub's entire job is to run scanners against arbitrary,
untrusted, attacker-supplied repositories. Two attack surfaces follow
directly from that:

1. Executable shadowing: on Windows, shutil.which() and CreateProcess's own
   executable search check the *process's* current directory before PATH.
   The old code called os.chdir(directory) before running any scanner, so a
   malicious repo shipping e.g. bandit.exe/eslint.cmd in its root would get
   resolved and executed *instead of* the real installed tool - full RCE on
   the scanning host from cloning a repo. Fixed by never moving the
   process's own cwd into scanned content; every scanner subprocess gets an
   explicit cwd= argument instead (see app.py's run_bluescrub() and every
   run_xxx() in utils/external_scanners.py).

2. Shell argument injection: .cmd/.bat files require cmd.exe as an
   interpreter on Windows, and cmd.exe re-parses its whole command line for
   metacharacters (&, |, (, ), %, !, ...). Fixed by validating every
   argument bound for a .cmd/.bat launch and refusing to run (returning an
   explicit failed ToolResult, not crashing) if any argument contains one.
"""

import os
import shutil
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.external_scanners import (  # noqa: E402
    run_cli_tool, _prepare_launch, _classify_exit_codes, UnsafeArgumentError,
)
from utils import scanner_status  # noqa: E402

# These tests exercise resolution/launch/safety behavior, not per-tool
# result classification (that's tests/test_scanner_classification.py) - a
# plain 0=clean/1=findings classifier is a fine stand-in everywhere below.
_classify = _classify_exit_codes()


# --- Executable shadowing --------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason=(
    "the CWD-before-PATH executable search this test exploits is a "
    "Windows-specific CreateProcess/shutil.which behavior (confirmed in "
    "Gate 2's investigation) - POSIX's exec search has no CWD-search step "
    "to shadow, so there's no equivalent vulnerability to test for here. "
    "test_run_cli_tool_never_chdirs_process below covers the platform-"
    "agnostic half of this property (run_cli_tool never calls os.chdir)."
))
def test_planted_executable_in_scanned_repo_is_not_executed(tmp_path, monkeypatch):
    """A malicious repo shipping a same-named tool must never get picked up
    over (or instead of) whatever's actually on PATH, just because the scan
    target directory is passed as cwd=."""
    # A "real, trusted" tool that lives on PATH.
    trusted_dir = tmp_path / "trusted_path_dir"
    trusted_dir.mkdir()
    sentinel_tool = "bluescrub_canary_tool"
    trusted_script = trusted_dir / f"{sentinel_tool}.bat"
    trusted_script.write_text("@echo TRUSTED_OUTPUT\n")

    # A "malicious repo" that plants a same-named file in its own root,
    # hoping it gets resolved/executed instead.
    evil_repo = tmp_path / "evil_repo"
    evil_repo.mkdir()
    shadow_marker = evil_repo / "shadow_ran.txt"
    evil_script = evil_repo / f"{sentinel_tool}.bat"
    evil_script.write_text(f'@echo off\r\necho SHADOWED > "{shadow_marker}"\r\n')

    monkeypatch.setenv("PATH", str(trusted_dir))
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)

    cwd_before = os.getcwd()
    result = run_cli_tool(sentinel_tool, [sentinel_tool], cwd=str(evil_repo), classify=_classify)
    cwd_after = os.getcwd()

    assert cwd_after == cwd_before, "run_cli_tool must never change the process's own cwd"
    assert "TRUSTED_OUTPUT" in result["display_output"], f"expected the trusted tool's output, got: {result}"
    assert not shadow_marker.exists(), "the repo-planted shim ran instead of / in addition to the trusted tool"


def test_run_cli_tool_never_chdirs_process(tmp_path, monkeypatch):
    """Direct regression for the root cause: resolving/launching a tool must
    not leave (or even transiently put) the process cwd inside the scanned
    directory."""
    real_chdir = os.chdir
    calls = []

    def spy_chdir(path):
        calls.append(path)
        return real_chdir(path)

    monkeypatch.setattr(os, "chdir", spy_chdir)

    scan_dir = tmp_path / "some_repo"
    scan_dir.mkdir()
    run_cli_tool("definitely_missing_tool_xyz", ["definitely_missing_tool_xyz"], cwd=str(scan_dir), classify=_classify)

    assert calls == [], f"run_cli_tool must not call os.chdir(), but it called: {calls}"


# --- Shell argument injection ----------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="cmd.exe shim launch path is Windows-only")
@pytest.mark.parametrize("payload", [
    "a&calc",
    "a|calc",
    "a(calc)",
    "a%TEMP%b",
    "a!b!",
    "a\"&calc",
])
def test_unsafe_characters_in_cmd_shim_args_are_rejected(tmp_path, payload):
    """Arguments bound for a .cmd/.bat interpreter must be validated as data,
    not silently handed to cmd.exe's own parser. Includes a harmless
    sentinel file so an actual injection would be observable without doing
    anything dangerous: if this test ever needs updating because injection
    *succeeded*, canary.txt would exist."""
    canary = tmp_path / "canary.txt"
    shim = tmp_path / "harmless.cmd"
    shim.write_text(f'@echo off\r\necho ran > "{canary}"\r\n')

    with pytest.raises(UnsafeArgumentError):
        _prepare_launch(str(shim), [payload])

    assert not canary.exists(), "a rejected/unsafe argument must never reach the shim at all"


@pytest.mark.skipif(os.name != "nt", reason="cmd.exe shim launch path is Windows-only")
def test_safe_arguments_reach_cmd_shim_as_literal_data(tmp_path):
    """The flip side of the rejection test: ordinary arguments (including
    ones with spaces, which ARE safe once quoted) still reach the script and
    are treated as plain data, not shell syntax."""
    out_file = tmp_path / "args_seen.txt"
    shim = tmp_path / "echoargs.cmd"
    shim.write_text('@echo off\r\necho %* > "' + str(out_file) + '"\r\n')

    argv = _prepare_launch(str(shim), ["hello world", "a-normal-arg"])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, shell=False, cwd=str(tmp_path))

    assert result.returncode == 0
    seen = out_file.read_text()
    assert "hello world" in seen
    assert "a-normal-arg" in seen


@pytest.mark.skipif(os.name != "nt", reason="cmd.exe shim launch path is Windows-only")
def test_end_to_end_injection_attempt_does_not_execute_second_command(tmp_path, monkeypatch):
    """Full run_cli_tool() path: an argument shaped like a classic shell
    injection payload must not cause a second command to run, proven via a
    harmless sentinel file that would exist if injection succeeded."""
    tool_dir = tmp_path / "path_dir"
    tool_dir.mkdir()
    canary = tmp_path / "injected.txt"
    shim = tool_dir / "greeter.cmd"
    shim.write_text("@echo off\r\necho hello %1\r\n")

    monkeypatch.setenv("PATH", str(tool_dir))

    payload = f'x&echo INJECTED>{canary}&echo '
    result = run_cli_tool("greeter", ["greeter", payload], cwd=str(tmp_path), classify=_classify)

    assert not canary.exists(), f"shell metacharacters in an argument executed a second command: {result}"
    assert result["status"] == scanner_status.ERROR  # rejected, not silently swallowed


# --- Deliberate .ps1 handling -----------------------------------------------

def test_ps1_is_not_treated_as_a_cmd_batch_file():
    """.ps1 must route to PowerShell's own -File invocation, not cmd.exe -
    cmd.exe cannot execute a .ps1 directly (no interpreter association)."""
    argv = _prepare_launch(r"C:\tools\lint.ps1", ["arg1"]) if os.name == "nt" else None
    if argv is None:
        pytest.skip("Windows-only launch path")
    assert argv[0].lower() not in ("cmd.exe", "cmd")
    assert "-File" in argv
    assert r"C:\tools\lint.ps1" in argv


# --- Native executables / non-Windows platforms -----------------------------

def test_native_executable_runs_without_a_shell_layer(tmp_path):
    """Non-.cmd/.bat/.ps1 resolutions (the common case, and the only case on
    POSIX) must be launched directly - no cmd.exe, no shell=True."""
    argv = _prepare_launch(sys.executable, ["-c", "print('ok')"])
    assert argv[0] == sys.executable
    assert "cmd.exe" not in " ".join(argv).lower()

    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, shell=False)
    assert result.returncode == 0
    assert "ok" in result.stdout


# --- Graceful degradation ---------------------------------------------------

def test_missing_executable_degrades_to_explicit_tool_result(tmp_path):
    result = run_cli_tool("nonexistent_tool_xyz", ["nonexistent_tool_xyz_binary_that_does_not_exist"], cwd=str(tmp_path), classify=_classify)
    assert result["status"] == scanner_status.UNAVAILABLE


def test_nonzero_exit_code_degrades_to_explicit_tool_result(tmp_path):
    """A scanner that runs but reports findings (or fails) via a non-zero
    exit code must still come back as a normal ToolResult-shaped dict."""
    argv = [sys.executable, "-c", "import sys; sys.exit(3)"]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, shell=False, cwd=str(tmp_path))
    assert result.returncode == 3  # sanity: the harness itself behaves as expected

    # Exercise the same path run_cli_tool takes for a resolved tool that
    # exits non-zero, using python itself as a stand-in "scanner" binary.
    # On Windows, shutil.which() resolves a bare name via PATHEXT, so a
    # ".bat" file matches a stem of "exit3". POSIX has no such extension
    # matching - shutil.which() needs an exact filename - so the POSIX
    # script deliberately has no extension at all (ordinary Unix
    # convention for an executable script) and its stem equals its name.
    script = tmp_path / ("exit3.bat" if os.name == "nt" else "exit3")
    if os.name == "nt":
        script.write_text("@echo off\r\nexit /b 3\r\n")
    else:
        script.write_text("#!/bin/sh\nexit 3\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

    tool_dir = tmp_path / "toolpath"
    tool_dir.mkdir()
    target = tool_dir / script.name
    shutil.move(str(script), str(target))

    orig_environ_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tool_dir) + os.pathsep + orig_environ_path
    try:
        # exit 3 matches neither _classify's pass_code (0) nor findings_codes
        # (1,), so it classifies as ERROR - but the point of this test is
        # that run_cli_tool degrades to a well-formed result either way,
        # rather than letting the non-zero exit escape as an exception.
        result = run_cli_tool(script.stem, [script.stem], cwd=str(tmp_path), classify=_classify)
    finally:
        os.environ["PATH"] = orig_environ_path

    assert result["status"] in (scanner_status.PASS, scanner_status.FINDINGS, scanner_status.ERROR)
    envelope = scanner_status.parse_result(result["result_json"])
    assert envelope is not None
    assert envelope["_exit_code"] == 3
