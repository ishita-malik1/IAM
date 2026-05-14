"""Composite priority engine.

Each finding receives a ``priority_score`` and a ``priority_rank`` (1 = top).
The top three findings additionally receive a plain-English
``projected_impact`` sentence.

Composite formula::

    priority_score = (severity_weight * 4)
                   + min(age_hours / 24, 15)
                   + principal_type_weight

    severity_weight: high = 10, medium = 5, low = 1
    principal_type_weight: ServicePrincipal = 5, User = 2, Group = 1
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_WEIGHT = {"high": 10, "medium": 5, "low": 1}
_PRINCIPAL_WEIGHT = {"serviceprincipal": 5, "user": 2, "group": 1}

_IMPACT_TEMPLATES: dict[str, str] = {
    "rbac_pim_bypass": (
        "If unresolved for 30 days, this standing privileged assignment "
        "continues to bypass your just-in-time controls, increasing exposure "
        "in any incident or audit during that period."
    ),
    "rbac_orphaned": (
        "If unresolved for 30 days, access belonging to a disabled account "
        "remains an active attack vector for credential-based entry into "
        "this role."
    ),
    "service_principal_elevated": (
        "If unresolved for 30 days, a non-human identity with broad "
        "permissions continues to represent an unmonitored lateral movement "
        "risk across all resources in this scope."
    ),
    "pim_stale": (
        "If unresolved for 30 days, elevated access that was intended as "
        "temporary becomes indistinguishable from a standing assignment, "
        "undermining the purpose of your PIM controls."
    ),
    "rbac_new": (
        "If unresolved for 30 days, an unconfirmed access change will appear "
        "in your next compliance review without a documented business "
        "justification."
    ),
    "rbac_stale": (
        "If unresolved for 30 days, standing privileged access continues "
        "without a documented review cycle, increasing audit and incident "
        "exposure."
    ),
    "pim_eligible_and_active": (
        "If unresolved for 30 days, this role is effectively ungoverned — "
        "the permanent active assignment bypasses the activation workflow "
        "that PIM was configured to enforce."
    ),
    "pim_repeated": (
        "If unresolved for 30 days, the repeated activation pattern will "
        "continue to generate noise in the audit log, masking other changes "
        "that may require attention."
    ),
    "pim_absent": (
        "Without PIM, all privileged access in this tenant operates on a "
        "standing basis. Every day without JIT controls is a day where "
        "over-provisioned access cannot be time-bounded or justified on "
        "demand."
    ),
}

_IMPACT_DEFAULT = (
    "If unresolved for 30 days, this finding will persist as an open risk "
    "item in future review cycles."
)


def _compute_score(finding: dict[str, Any]) -> float:
    severity = (finding.get("severity") or "low").lower()
    severity_weight = _SEVERITY_WEIGHT.get(severity, 1)
    age_hours = float(finding.get("age_hours") or 0.0)
    age_component = min(age_hours / 24.0, 15.0)
    principal_type = (finding.get("principal_type") or "").lower()
    principal_weight = _PRINCIPAL_WEIGHT.get(principal_type, 0)
    return round(severity_weight * 4 + age_component + principal_weight, 4)


def _projected_impact(finding: dict[str, Any]) -> str:
    return _IMPACT_TEMPLATES.get(
        finding.get("finding_type", ""), _IMPACT_DEFAULT
    )


def prioritize(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score, rank, and annotate the top-three findings.

    Findings are mutated in place. The returned list is the same reference,
    sorted by ``priority_rank`` ascending so callers can iterate directly.
    """

    if not findings:
        return findings

    for finding in findings:
        finding["priority_score"] = _compute_score(finding)

    severity_order = {"high": 0, "medium": 1, "low": 2}

    findings.sort(
        key=lambda f: (
            -float(f["priority_score"] or 0.0),
            severity_order.get((f.get("severity") or "low").lower(), 3),
            -float(f.get("age_hours") or 0.0),
        )
    )

    for index, finding in enumerate(findings, start=1):
        finding["priority_rank"] = index

    for finding in findings[:3]:
        finding["projected_impact"] = _projected_impact(finding)

    logger.info(
        "Priority engine: top 3 selected and ranked from %d findings.",
        len(findings),
    )
    return findings
