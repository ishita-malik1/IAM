"""Severity assignment.

The first matching rule wins. Severities are written in place onto each
finding's ``severity`` field.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _severity_for(finding: dict[str, Any]) -> str:
    finding_type = finding.get("finding_type", "")
    age = float(finding.get("age_hours") or 0.0)

    if finding_type == "rbac_pim_bypass":
        return "high"
    if finding_type == "rbac_orphaned":
        return "high"
    if finding_type == "service_principal_elevated":
        return "high"
    if finding_type == "pim_stale" and age >= 168.0:
        return "high"
    if finding_type == "pim_eligible_and_active":
        return "high"

    if finding_type == "rbac_new" and age >= 48.0:
        return "medium"
    if finding_type == "pim_stale" and age >= 24.0:
        return "medium"
    if finding_type == "pim_no_justification":
        return "medium"
    if finding_type == "pim_repeated":
        return "medium"
    if finding_type == "pim_absent":
        return "medium"

    if finding_type == "rbac_new" and age < 48.0:
        return "low"
    if finding_type == "rbac_removed":
        return "low"

    return "low"


def score_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate every finding with a ``severity`` value.

    Returns the same list reference (mutated in place) for chaining.
    """

    for finding in findings:
        finding["severity"] = _severity_for(finding)
    if findings:
        counts = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        logger.info(
            "Risk scorer: %d high, %d medium, %d low.",
            counts["high"],
            counts["medium"],
            counts["low"],
        )
    return findings
