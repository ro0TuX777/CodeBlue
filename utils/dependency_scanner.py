"""
Software Composition Analysis (SCA) via OSV-Scanner.

Wraps Google's osv-scanner CLI (https://github.com/google/osv-scanner) to check
a scanned repository's dependency manifests/lockfiles (requirements.txt,
package-lock.json, go.sum, Cargo.lock, pom.xml, etc.) against the OSV
vulnerability database. Unlike Safety, which only understands Python
dependencies, this covers every ecosystem osv-scanner supports, which matters
because CodeBlue scans arbitrary cloned repositories, not just Python ones.

osv-scanner is a standalone Go binary, not a pip package, so it is treated the
same way GitLeaks/TFSec are: an optional external tool that this module
degrades gracefully without if it isn't on PATH.
"""

import json
import logging
import shutil
import subprocess

from utils import scanner_status

logger = logging.getLogger(__name__)

OSV_SCANNER_BINARY = 'osv-scanner'
SCAN_TIMEOUT_SECONDS = 300

# OSV's database_specific.severity values, normalized to CodeBlue's severity labels.
_SEVERITY_MAP = {
    'CRITICAL': 'High',
    'HIGH': 'High',
    'MODERATE': 'Medium',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
}


def is_osv_scanner_available() -> bool:
    """Check whether the osv-scanner binary is on PATH."""
    return shutil.which(OSV_SCANNER_BINARY) is not None


def _severity_from_vuln(vuln: dict) -> str:
    """Best-effort severity extraction from an OSV vulnerability record."""
    db_severity = vuln.get('database_specific', {}).get('severity')
    if isinstance(db_severity, str) and db_severity.upper() in _SEVERITY_MAP:
        return _SEVERITY_MAP[db_severity.upper()]

    # Fall back to any CVSS vector string in the severity list; presence of a
    # numeric score isn't parsed here, so this only distinguishes "some CVSS
    # data exists" from "none at all". Default to Medium either way.
    if vuln.get('severity'):
        return 'Medium'

    return 'Medium'


def _parse_osv_json(raw_output: str) -> dict:
    """Flatten osv-scanner's nested JSON into a list of per-vulnerability findings."""
    findings = []
    packages_checked = 0
    packages_with_vulns = set()

    try:
        data = json.loads(raw_output) if raw_output.strip() else {}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse osv-scanner JSON output: {e}")
        return {'findings': [], 'packages_checked': 0, 'vulnerable_package_count': 0}

    for result in data.get('results', []):
        source_path = result.get('source', {}).get('path', 'unknown')
        for pkg_entry in result.get('packages', []):
            packages_checked += 1
            package = pkg_entry.get('package', {})
            pkg_name = package.get('name', 'unknown')
            pkg_version = package.get('version', 'unknown')
            ecosystem = package.get('ecosystem', 'unknown')

            vulns = pkg_entry.get('vulnerabilities', [])
            if vulns:
                packages_with_vulns.add((ecosystem, pkg_name, pkg_version))

            for vuln in vulns:
                findings.append({
                    'id': vuln.get('id', 'UNKNOWN'),
                    'aliases': vuln.get('aliases', []),
                    'summary': vuln.get('summary') or vuln.get('details', 'No summary available')[:300],
                    'severity': _severity_from_vuln(vuln),
                    'package': pkg_name,
                    'version': pkg_version,
                    'ecosystem': ecosystem,
                    'file_path': source_path,
                })

    return {
        'findings': findings,
        'packages_checked': packages_checked,
        'vulnerable_package_count': len(packages_with_vulns),
    }


def run_osv_scan(repo_path: str) -> dict:
    """
    Run osv-scanner against a repository's dependency manifests.

    Returns a dict with:
      - status: one of scanner_status.{PASS,FINDINGS,UNAVAILABLE,ERROR}
      - available: whether osv-scanner was found on PATH (kept for
        backward compatibility with any existing caller reading it)
      - findings: list of normalized vulnerability dicts
      - packages_checked / vulnerable_package_count: counts for scoring
      - summary_text: human-readable block to append to the scan output
      - error: set on failure

    osv-scanner's own documented exit codes are 0 = no vulnerabilities found,
    1 = vulnerabilities found; anything else (127, etc.) is a genuine
    execution failure, not "clean" or "findings".
    """
    if not is_osv_scanner_available():
        message = (
            "osv-scanner is not installed or not on PATH. "
            "Dependency vulnerability scanning (SCA) was skipped. "
            "See install_binary_tools.sh / install_windows_tools.ps1.\n"
        )
        logger.warning(message.strip())
        return {
            'status': scanner_status.UNAVAILABLE,
            'available': False,
            'findings': [],
            'packages_checked': 0,
            'vulnerable_package_count': 0,
            'summary_text': message,
            'error': 'osv-scanner not found on PATH',
        }

    try:
        # osv-scanner's real CLI (confirmed against the pinned v1.9.2
        # binary) is `osv-scanner scan [options] [directories...]` - there
        # is no `source` subcommand. The literal 'source' previously here
        # was passed as an extra (nonexistent) directory argument, which
        # made every single scan fail immediately ("stat source: no such
        # file or directory") without ever reaching repo_path at all.
        result = subprocess.run(
            [OSV_SCANNER_BINARY, 'scan', '--format', 'json', '--recursive', repo_path],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        # osv-scanner exits 1 when it finds vulnerabilities and 0 when clean;
        # anything else (127, etc.) indicates a real execution failure.
        if result.returncode not in (0, 1):
            error_msg = f"osv-scanner exited with code {result.returncode}: {result.stderr.strip()}"
            logger.error(error_msg)
            return {
                'status': scanner_status.ERROR,
                'available': True,
                'findings': [],
                'packages_checked': 0,
                'vulnerable_package_count': 0,
                'summary_text': error_msg + "\n",
                'error': error_msg,
            }

        parsed = _parse_osv_json(result.stdout)

    except subprocess.TimeoutExpired:
        error_msg = f"osv-scanner timed out after {SCAN_TIMEOUT_SECONDS} seconds"
        logger.error(error_msg)
        return {
            'status': scanner_status.ERROR,
            'available': True,
            'findings': [],
            'packages_checked': 0,
            'vulnerable_package_count': 0,
            'summary_text': error_msg + "\n",
            'error': error_msg,
        }
    except Exception as e:
        error_msg = f"Error running osv-scanner: {str(e)}"
        logger.error(error_msg)
        logger.exception("osv-scanner error details:")
        return {
            'status': scanner_status.ERROR,
            'available': True,
            'findings': [],
            'packages_checked': 0,
            'vulnerable_package_count': 0,
            'summary_text': error_msg + "\n",
            'error': error_msg,
        }

    findings = parsed['findings']
    packages_checked = parsed['packages_checked']
    vulnerable_count = parsed['vulnerable_package_count']

    high = sum(1 for f in findings if f['severity'] == 'High')
    medium = sum(1 for f in findings if f['severity'] == 'Medium')
    low = sum(1 for f in findings if f['severity'] == 'Low')

    # The "Checked N packages" / "Found N vulnerable" phrasing intentionally
    # matches the regexes SecurityPostureScorer._calculate_dependencies_score
    # already looks for, so OSV-Scanner results feed the existing dependencies
    # score without any changes to security_posture.py.
    summary_lines = [
        f"OSV-Scanner: Checked {packages_checked} packages, Found {vulnerable_count} vulnerable dependencies "
        f"({len(findings)} total findings: {high} High, {medium} Medium, {low} Low).",
    ]
    for f in findings:
        summary_lines.append(
            f"  [{f['severity']}] {f['ecosystem']}:{f['package']}@{f['version']} - {f['id']} "
            f"({f['file_path']}): {f['summary']}"
        )
    summary_text = "\n".join(summary_lines) + "\n\n"

    return {
        'status': scanner_status.FINDINGS if findings else scanner_status.PASS,
        'available': True,
        'findings': findings,
        'packages_checked': packages_checked,
        'vulnerable_package_count': vulnerable_count,
        'summary_text': summary_text,
        'error': None,
    }
