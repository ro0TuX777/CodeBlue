"""
Lightweight license compliance check for scanned repositories.

CodeBlue already pins `license-expression` and `spdx-tools` in requirements.txt
(for SPDX/CycloneDX-adjacent tooling) but nothing in the codebase used them.
This module puts them to work for the one thing they're actually built for:

  1. Parsing/validating any `SPDX-License-Identifier:` headers found in source
     files, so malformed expressions get flagged.
  2. Classifying the repository's own declared license (from a root
     LICENSE/COPYING file) and any per-file SPDX headers, flagging strong or
     weak copyleft licenses (GPL/AGPL/LGPL/MPL/...) that a team pulling code
     from a scanned repo would want to know about before reusing it.

This is deliberately scoped to what's discoverable locally, without network
calls: it does not resolve the licenses of third-party *dependencies* (that
would require querying PyPI/npm/etc. per package), only what the repository
itself declares about its own code.
"""

import logging
import os
import re

from utils import scanner_status

logger = logging.getLogger(__name__)

try:
    from license_expression import Licensing
    _LICENSING = Licensing()
except ImportError:  # pragma: no cover - guards against an unpinned/removed dep
    _LICENSING = None
    logger.warning("license_expression is not installed; license header checks will be skipped.")

# Substring -> (category, severity). Checked case-insensitively against each
# SPDX license key. Order matters: AGPL/LGPL must be checked before the bare
# "GPL" substring they both contain.
_COPYLEFT_RULES = [
    ('AGPL', 'strong copyleft (network use triggers source disclosure)', 'High'),
    ('SSPL', 'strong copyleft (source-available, network use)', 'High'),
    ('LGPL', 'weak copyleft (dynamic linking generally exempt)', 'Medium'),
    ('GPL', 'strong copyleft (derivative works must be released under GPL)', 'High'),
    ('MPL', 'weak copyleft (file-level)', 'Low'),
    ('EPL', 'weak copyleft (file-level)', 'Low'),
    ('CDDL', 'weak copyleft (file-level)', 'Low'),
    ('OSL', 'weak copyleft', 'Low'),
]

# Root-level license file text -> declared license label, checked in order.
_LICENSE_TEXT_MARKERS = [
    ('GNU AFFERO GENERAL PUBLIC LICENSE', 'AGPL-3.0'),
    ('GNU LESSER GENERAL PUBLIC LICENSE', 'LGPL'),
    ('GNU GENERAL PUBLIC LICENSE', 'GPL'),
    ('Mozilla Public License', 'MPL-2.0'),
    ('Apache License', 'Apache-2.0'),
    ('BSD 3-Clause', 'BSD-3-Clause'),
    ('BSD 2-Clause', 'BSD-2-Clause'),
    ('Permission is hereby granted, free of charge', 'MIT'),
    ('ISC License', 'ISC'),
]

_LICENSE_FILENAMES = [
    'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'LICENSE.rst',
    'LICENCE', 'LICENCE.txt', 'LICENCE.md',
    'COPYING', 'COPYING.txt', 'COPYING.LESSER',
]

# Requires a real comment marker immediately before the tag, so prose that
# merely mentions "SPDX-License-Identifier:" (e.g. in a docstring) doesn't
# match. The captured expression is intentionally unrestricted in character
# class - malformed expressions are caught by license_expression.parse()
# below, not by this regex, so garbage input is flagged rather than silently
# skipped.
_SPDX_HEADER_RE = re.compile(
    r'^[ \t]*(?:#|//|/\*!?|--|<!--)[ \t]*SPDX-License-Identifier:[ \t]*'
    r'(.+?)[ \t]*(?:\*/|-->)?[ \t]*$',
    re.MULTILINE,
)

_SCAN_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.java', '.kt', '.c', '.h',
    '.cpp', '.hpp', '.cc', '.rb', '.php', '.rs', '.cs', '.sh', '.swift', '.scala',
}

_SKIP_DIRS = {
    '.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build',
    'vendor', 'analysis_results', '.tox', '.mypy_cache', '.pytest_cache', 'target',
}

_MAX_FILES_SCANNED = 20000
_HEADER_READ_BYTES = 4096


def _classify(expression_text: str):
    """Return (category, severity) for the first copyleft rule matched, else None."""
    upper = expression_text.upper()
    for keyword, category, severity in _COPYLEFT_RULES:
        if keyword in upper:
            return category, severity
    return None


def _find_declared_license(repo_path: str):
    """Look for a root-level LICENSE/COPYING file and classify its text."""
    for filename in _LICENSE_FILENAMES:
        file_path = os.path.join(repo_path, filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(8192)
            except OSError as e:
                logger.debug(f"Could not read license file {file_path}: {e}")
                continue

            for marker, label in _LICENSE_TEXT_MARKERS:
                if marker.lower() in content.lower():
                    # GPL text distinguishes version in the first couple of lines.
                    if label == 'GPL':
                        if 'version 3' in content[:400].lower():
                            label = 'GPL-3.0'
                        elif 'version 2' in content[:400].lower():
                            label = 'GPL-2.0'
                    elif label == 'LGPL':
                        if 'version 3' in content[:400].lower():
                            label = 'LGPL-3.0'
                        elif 'version 2.1' in content[:400].lower():
                            label = 'LGPL-2.1'
                    return filename, label

            return filename, 'Unknown/Custom'

    return None, None


def _scan_spdx_headers(repo_path: str):
    """Walk source files looking for SPDX-License-Identifier headers."""
    findings = []
    headers_found = 0
    files_scanned = 0

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        for filename in files:
            if files_scanned >= _MAX_FILES_SCANNED:
                return findings, headers_found

            ext = os.path.splitext(filename)[1]
            if ext not in _SCAN_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    head = f.read(_HEADER_READ_BYTES)
            except OSError as e:
                logger.debug(f"Could not read {file_path}: {e}")
                continue

            files_scanned += 1
            match = _SPDX_HEADER_RE.search(head)
            if not match:
                continue

            headers_found += 1
            raw_expr = match.group(1).strip()
            rel_path = os.path.relpath(file_path, repo_path)

            if _LICENSING is None:
                continue

            try:
                parsed = _LICENSING.parse(raw_expr, validate=False)
            except Exception as e:
                findings.append({
                    'title': 'Unparseable SPDX-License-Identifier',
                    'severity': 'Low',
                    'description': f"Malformed SPDX expression '{raw_expr}': {str(e)}",
                    'file_path': rel_path,
                    'line_number': head[:match.start()].count('\n') + 1,
                    'code_snippet': match.group(0),
                    'recommendation': 'Fix the SPDX-License-Identifier so it is a valid SPDX license expression.',
                })
                continue

            if parsed is None:
                continue

            for symbol in parsed.symbols:
                classification = _classify(str(symbol))
                if classification:
                    category, severity = classification
                    findings.append({
                        'title': f'Copyleft license detected: {symbol}',
                        'severity': severity,
                        'description': f"{symbol} is a {category}.",
                        'file_path': rel_path,
                        'line_number': head[:match.start()].count('\n') + 1,
                        'code_snippet': match.group(0),
                        'recommendation': (
                            'Review whether this file\'s license is compatible with how this '
                            'codebase intends to use/redistribute it.'
                        ),
                    })

    return findings, headers_found


def analyze_licenses(repo_path: str) -> dict:
    """
    Run the license compliance check against a repository.

    Returns a dict with the repo's declared license, any copyleft findings
    from per-file SPDX headers, and a summary_text block for the scan output.
    """
    declared_file, declared_license = _find_declared_license(repo_path)
    declared_classification = _classify(declared_license) if declared_license else None

    findings, headers_found = _scan_spdx_headers(repo_path)

    if declared_classification:
        category, severity = declared_classification
        findings.insert(0, {
            'title': f'Repository declared license: {declared_license}',
            'severity': severity,
            'description': f"{declared_license} ({category}), declared in {declared_file}.",
            'file_path': declared_file,
            'line_number': 1,
            'code_snippet': '',
            'recommendation': (
                'Confirm this copyleft license is acceptable before vendoring or redistributing this code.'
            ),
        })

    summary_lines = [
        f"License Check: declared license = {declared_license or 'not found'} "
        f"({declared_file or 'no LICENSE/COPYING file'}), "
        f"{headers_found} SPDX-License-Identifier header(s) found, "
        f"{len(findings)} finding(s) flagged.",
    ]
    for f in findings:
        summary_lines.append(f"  [{f['severity']}] {f['title']} ({f['file_path']})")
    summary_text = "\n".join(summary_lines) + "\n\n"

    return {
        'status': scanner_status.FINDINGS if findings else scanner_status.PASS,
        'declared_license': declared_license,
        'declared_license_file': declared_file,
        'headers_found': headers_found,
        'findings': findings,
        'summary_text': summary_text,
    }
