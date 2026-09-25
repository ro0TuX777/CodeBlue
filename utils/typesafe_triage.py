"""
TypeSafe-based triage for static-analysis findings.

Bandit's plain-text fallback output and Pylint's output carry no reliable
severity field, so the security_issues() view previously guessed severity
from substrings in the issue id (e.g. "HIGH" in an id) and decided whether
a Pylint finding was security-relevant by checking for the words
"security" or "vuln" in its message. Both are brittle heuristics that miss
anything not spelled that way. This module replaces them with a calibrated
TypeSafe judgment per finding.
"""

import logging
from typing import Any, Dict, List, Tuple

from typesafe_sdk import Noul, Score, TypeSafeClient, TypeSafeError

logger = logging.getLogger(__name__)

_SEVERITY_LEVELS = ["Low", "Medium", "High"]

_SEVERITY_CRITERIA = [
    "Low impact: a style, formatting, or readability nit with no meaningful "
    "security or correctness risk.",
    "Medium impact: a real correctness or maintainability issue, or a "
    "security weakness that needs specific conditions to be exploitable.",
    "High impact: a serious security vulnerability or correctness bug that "
    "is straightforward to trigger or exploit.",
]


def triage_findings(findings: List[Dict[str, Any]]) -> List[Tuple[str, bool, float]]:
    """Score severity and security-relevance for a batch of findings.

    Each item in `findings` needs `tool`, `issue_id`, `message`, and
    `file_path` keys. Returns one (severity_label, is_security_relevant,
    confidence) tuple per input finding, in the same order.

    If the TypeSafe request fails, every item falls back to ("Medium",
    True, 0.0) — a security scanner should surface a finding it's unsure
    about rather than silently drop it.
    """
    if not findings:
        return []

    state = {
        "findings": [
            {
                "tool": finding["tool"],
                "issue_id": finding["issue_id"],
                "message": finding["message"],
                "file_path": finding["file_path"],
            }
            for finding in findings
        ]
    }

    questions = {}
    for i in range(len(findings)):
        questions[f"severity_{i}"] = Score(
            instructions=(
                f"How severe is the static-analysis finding at "
                f"`findings[{i}]` for software security and correctness?"
            ),
            criteria=_SEVERITY_CRITERIA,
        )
        questions[f"relevant_{i}"] = Noul(
            instructions=(
                f"Is the static-analysis finding at `findings[{i}]` a "
                "security vulnerability or security-relevant weakness?"
            ),
            criteria={
                "true": "The finding describes a security vulnerability or "
                "a weakness an attacker could exploit.",
                "false": "The finding is about style, formatting, naming, "
                "complexity, or another code-quality concern with no "
                "security implication.",
            },
        )

    try:
        with TypeSafeClient() as client:
            response = client.system_one(state=state, questions=questions)
    except TypeSafeError as exc:
        logger.error("TypeSafe triage request failed, using fallback severity: %s", exc)
        return [("Medium", True, 0.0) for _ in findings]

    results = []
    for i in range(len(findings)):
        severity_answer = response.scores[f"severity_{i}"]
        level = round(severity_answer.score)
        level = max(0, min(level, len(_SEVERITY_LEVELS) - 1))
        is_relevant = response.nouls[f"relevant_{i}"].noul > 0.5
        results.append((_SEVERITY_LEVELS[level], is_relevant, severity_answer.confidence))
    return results
