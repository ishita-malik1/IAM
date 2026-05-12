"""Diff engine: turn two snapshots into a list of structured findings.

Given the current snapshot, the previous snapshot (or ``None`` for a baseline
run), and the :class:`PreflightResult`, the diff engine emits findings that
conform to the schema documented in the project README. It also computes a
:class:`DataQuality` block so the report can disclose any gaps in coverage.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from src.preflight import PreflightResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DataQuality:
    """Coverage report attached to every digest run."""

    pim_data_available: bool
    arm_data_available: bool
    signal_conflict_count: int
    event_delay_detected: bool
    event_delay_hours: Optional[float]


@dataclass
class DiffResult:
    """Structured output of the diff engine."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    is_baseline_run: bool = False
    current_snapshot_timestamp: Optional[str] = None
    previous_snapshot_timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_PRIVILEGED_ROLE_NAMES = {"owner", "contributor"}


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 string into a timezone-aware UTC datetime."""

    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        logger.debug("Could not parse datetime %r", value)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hours_between(later: datetime, earlier: datetime) -> float:
    return max((later - earlier).total_seconds() / 3600.0, 0.0)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_subscription_scope(scope: str) -> bool:
    if not scope:
        return False
    s = scope.lower().strip("/")
    parts = s.split("/")
    return len(parts) == 2 and parts[0] == "subscriptions"


def _is_resource_group_scope(scope: str) -> bool:
    if not scope:
        return False
    s = scope.lower()
    return "/resourcegroups/" in s


def _is_orphaned_principal(assignment: dict[str, Any]) -> bool:
    """Best-effort detection of orphan assignments using snapshot data alone.

    A principal that the directory could not expand will lack a display name
    distinct from its id. The principal type also collapses to ``Unknown``.
    Without write access we cannot verify the user's ``accountEnabled`` flag
    directly, so we lean on the side effects of the ``$expand=principal``
    response.
    """

    principal_id = assignment.get("principal_id") or ""
    display_name = assignment.get("principal_display_name") or ""
    principal_type = (assignment.get("principal_type") or "").lower()
    if not principal_id:
        return False
    if principal_type == "unknown":
        return True
    if display_name and display_name == principal_id:
        return True
    return False


def _stale_pim_threshold_hours() -> float:
    raw = os.environ.get("STALE_PIM_THRESHOLD_HOURS", "24")
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "STALE_PIM_THRESHOLD_HOURS=%r is not a number; defaulting to 24.", raw
        )
        return 24.0


def _build_finding(
    *,
    finding_type: str,
    principal_id: str,
    principal_display_name: str,
    principal_type: str,
    role_definition_name: str,
    scope: str,
    detected_at: datetime,
    age_hours: float,
    activation_count: Optional[int] = None,
) -> dict[str, Any]:
    """Create a finding dict with the schema fields downstream stages will
    enrich."""

    return {
        "finding_id": str(uuid.uuid4()),
        "finding_type": finding_type,
        "principal_id": principal_id,
        "principal_display_name": principal_display_name or principal_id or "Unknown",
        "principal_type": principal_type or "Unknown",
        "role_definition_name": role_definition_name or "Unknown role",
        "scope": scope or "/",
        "detected_at": _utc_iso(detected_at),
        "age_hours": round(age_hours, 2),
        "activation_count": activation_count,
        "severity": "low",
        "priority_rank": None,
        "priority_score": None,
        "projected_impact": None,
        "action_item": "",
        "remediation_command": "",
        "recommended_owner": "",
    }


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _index_rbac(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item.get("id") or "": item for item in items if item.get("id")}


def _detect_rbac_changes(
    current_rbac: list[dict[str, Any]],
    previous_rbac: list[dict[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    """Emit ``rbac_new``, ``rbac_removed``, and ``rbac_escalated`` findings."""

    findings: list[dict[str, Any]] = []
    current_index = _index_rbac(current_rbac)
    previous_index = _index_rbac(previous_rbac)

    new_ids = current_index.keys() - previous_index.keys()
    removed_ids = previous_index.keys() - current_index.keys()

    new_findings: dict[str, dict[str, Any]] = {}
    for assignment_id in new_ids:
        item = current_index[assignment_id]
        created = _parse_iso(item.get("created_date_time")) or now
        age = _hours_between(now, created)
        finding = _build_finding(
            finding_type="rbac_new",
            principal_id=item.get("principal_id", ""),
            principal_display_name=item.get("principal_display_name", ""),
            principal_type=item.get("principal_type", ""),
            role_definition_name=item.get("role_definition_name", ""),
            scope=item.get("scope", ""),
            detected_at=now,
            age_hours=age,
        )
        new_findings[assignment_id] = finding

    removed_findings: dict[str, dict[str, Any]] = {}
    for assignment_id in removed_ids:
        item = previous_index[assignment_id]
        created = _parse_iso(item.get("created_date_time")) or now
        age = _hours_between(now, created)
        finding = _build_finding(
            finding_type="rbac_removed",
            principal_id=item.get("principal_id", ""),
            principal_display_name=item.get("principal_display_name", ""),
            principal_type=item.get("principal_type", ""),
            role_definition_name=item.get("role_definition_name", ""),
            scope=item.get("scope", ""),
            detected_at=now,
            age_hours=age,
        )
        removed_findings[assignment_id] = finding

    # Detect escalation by pairing removed RG-scoped assignments with new
    # subscription-scoped assignments for the same (principal, role).
    consumed_new: set[str] = set()
    consumed_removed: set[str] = set()
    for removed_id, removed in removed_findings.items():
        if not _is_resource_group_scope(removed["scope"]):
            continue
        for new_id, new in new_findings.items():
            if new_id in consumed_new:
                continue
            if not _is_subscription_scope(new["scope"]):
                continue
            if (
                new["principal_id"] == removed["principal_id"]
                and new["role_definition_name"] == removed["role_definition_name"]
            ):
                consumed_new.add(new_id)
                consumed_removed.add(removed_id)
                escalated = _build_finding(
                    finding_type="rbac_escalated",
                    principal_id=new["principal_id"],
                    principal_display_name=new["principal_display_name"],
                    principal_type=new["principal_type"],
                    role_definition_name=new["role_definition_name"],
                    scope=new["scope"],
                    detected_at=now,
                    age_hours=new["age_hours"],
                )
                findings.append(escalated)
                break

    findings.extend(
        f for fid, f in new_findings.items() if fid not in consumed_new
    )
    findings.extend(
        f for fid, f in removed_findings.items() if fid not in consumed_removed
    )
    return findings


def _detect_orphaned(
    current_rbac: list[dict[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    findings = []
    for item in current_rbac:
        if _is_orphaned_principal(item):
            created = _parse_iso(item.get("created_date_time")) or now
            findings.append(
                _build_finding(
                    finding_type="rbac_orphaned",
                    principal_id=item.get("principal_id", ""),
                    principal_display_name=item.get("principal_display_name", ""),
                    principal_type=item.get("principal_type", ""),
                    role_definition_name=item.get("role_definition_name", ""),
                    scope=item.get("scope", ""),
                    detected_at=now,
                    age_hours=_hours_between(now, created),
                )
            )
    return findings


def _detect_pim_bypass(
    current_rbac: list[dict[str, Any]],
    arm_rbac: list[dict[str, Any]],
    pim_configured: bool,
    now: datetime,
) -> list[dict[str, Any]]:
    if not pim_configured:
        return []

    findings: list[dict[str, Any]] = []

    for item in current_rbac:
        role_name = (item.get("role_definition_name") or "").lower()
        if role_name not in _PRIVILEGED_ROLE_NAMES:
            continue
        if item.get("is_pim_managed"):
            continue
        created = _parse_iso(item.get("created_date_time")) or now
        findings.append(
            _build_finding(
                finding_type="rbac_pim_bypass",
                principal_id=item.get("principal_id", ""),
                principal_display_name=item.get("principal_display_name", ""),
                principal_type=item.get("principal_type", ""),
                role_definition_name=item.get("role_definition_name", ""),
                scope=item.get("scope", ""),
                detected_at=now,
                age_hours=_hours_between(now, created),
            )
        )

    for item in arm_rbac:
        role_name = (item.get("role_definition_name") or "").lower()
        if role_name not in _PRIVILEGED_ROLE_NAMES:
            continue
        created = _parse_iso(item.get("created_on")) or now
        principal_id = item.get("principal_id", "")
        findings.append(
            _build_finding(
                finding_type="rbac_pim_bypass",
                principal_id=principal_id,
                principal_display_name=principal_id,
                principal_type=item.get("principal_type", ""),
                role_definition_name=item.get("role_definition_name", ""),
                scope=item.get("scope", ""),
                detected_at=now,
                age_hours=_hours_between(now, created),
            )
        )

    return findings


def _detect_service_principal_elevated(
    current_rbac: list[dict[str, Any]],
    arm_rbac: list[dict[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(item: dict[str, Any], created_field: str) -> None:
        principal_type = (item.get("principal_type") or "").lower()
        if principal_type != "serviceprincipal":
            return
        role_name = (item.get("role_definition_name") or "").lower()
        if role_name not in _PRIVILEGED_ROLE_NAMES:
            return
        principal_id = item.get("principal_id", "")
        scope = item.get("scope", "")
        role = item.get("role_definition_name", "")
        key = (principal_id, role.lower(), scope.lower())
        if key in seen:
            return
        seen.add(key)
        created = _parse_iso(item.get(created_field)) or now
        findings.append(
            _build_finding(
                finding_type="service_principal_elevated",
                principal_id=principal_id,
                principal_display_name=item.get("principal_display_name")
                or principal_id,
                principal_type="ServicePrincipal",
                role_definition_name=role,
                scope=scope,
                detected_at=now,
                age_hours=_hours_between(now, created),
            )
        )

    for item in current_rbac:
        emit(item, "created_date_time")
    for item in arm_rbac:
        emit(item, "created_on")
    return findings


def _detect_pim_findings(
    current_pim: list[dict[str, Any]],
    previous_pim: list[dict[str, Any]],
    pim_configured: bool,
    now: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(stale + no-justification + repeated, eligible_and_active)``.

    Splitting the return value lets the caller suppress the eligible-and-active
    detector without re-walking the activation list.
    """

    if not pim_configured or not current_pim:
        return [], []

    stale_threshold = _stale_pim_threshold_hours()
    findings: list[dict[str, Any]] = []

    # ---- pim_stale & pim_no_justification (per activation) ----------------
    for activation in current_pim:
        if (activation.get("assignment_type") or "").lower() != "activated":
            continue
        start = _parse_iso(activation.get("start_date_time"))
        if not start:
            continue
        age = _hours_between(now, start)
        end = _parse_iso(activation.get("end_date_time"))
        end_in_future_or_null = end is None or end > now

        if age >= stale_threshold and end_in_future_or_null:
            findings.append(
                _build_finding(
                    finding_type="pim_stale",
                    principal_id=activation.get("principal_id", ""),
                    principal_display_name=activation.get(
                        "principal_display_name", ""
                    ),
                    principal_type=activation.get("principal_type", ""),
                    role_definition_name=activation.get("role_definition_name", ""),
                    scope=activation.get("scope", ""),
                    detected_at=now,
                    age_hours=age,
                )
            )

        justification = (activation.get("justification") or "").strip()
        if not justification and 24.0 <= age <= 48.0:
            findings.append(
                _build_finding(
                    finding_type="pim_no_justification",
                    principal_id=activation.get("principal_id", ""),
                    principal_display_name=activation.get(
                        "principal_display_name", ""
                    ),
                    principal_type=activation.get("principal_type", ""),
                    role_definition_name=activation.get("role_definition_name", ""),
                    scope=activation.get("scope", ""),
                    detected_at=now,
                    age_hours=age,
                )
            )

    # ---- pim_repeated: 3+ activations per (principal, role) in 7 days -----
    seven_days_ago = now - timedelta(days=7)
    history: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}

    for source in (previous_pim or [], current_pim):
        for activation in source:
            if (activation.get("assignment_type") or "").lower() != "activated":
                continue
            start = _parse_iso(activation.get("start_date_time"))
            if not start or start < seven_days_ago:
                continue
            principal_id = activation.get("principal_id", "")
            role = activation.get("role_definition_name", "")
            key = (principal_id, role.lower())
            history.setdefault(key, {})[activation.get("id", "") or str(id(activation))] = activation

    for (_, _), records in history.items():
        if len(records) < 3:
            continue
        sample = next(iter(records.values()))
        most_recent_start = max(
            (_parse_iso(a.get("start_date_time")) or now for a in records.values()),
            default=now,
        )
        age = _hours_between(now, most_recent_start)
        findings.append(
            _build_finding(
                finding_type="pim_repeated",
                principal_id=sample.get("principal_id", ""),
                principal_display_name=sample.get("principal_display_name", ""),
                principal_type=sample.get("principal_type", ""),
                role_definition_name=sample.get("role_definition_name", ""),
                scope=sample.get("scope", ""),
                detected_at=now,
                age_hours=age,
                activation_count=len(records),
            )
        )

    return findings, []


def _detect_eligible_and_active(
    current_pim: list[dict[str, Any]],
    current_rbac: list[dict[str, Any]],
    pim_configured: bool,
    now: datetime,
) -> list[dict[str, Any]]:
    """Same principal+role appearing as Eligible (PIM) and as a permanent
    direct assignment (Graph RBAC) at the same time."""

    if not pim_configured:
        return []

    findings: list[dict[str, Any]] = []
    eligible_pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for activation in current_pim:
        if (activation.get("assignment_type") or "").lower() != "eligible":
            continue
        principal_id = activation.get("principal_id", "")
        role = activation.get("role_definition_name", "")
        eligible_pairs[(principal_id, role.lower())] = activation

    seen: set[tuple[str, str]] = set()
    for assignment in current_rbac:
        if assignment.get("is_pim_managed"):
            continue
        principal_id = assignment.get("principal_id", "")
        role = assignment.get("role_definition_name", "")
        key = (principal_id, role.lower())
        if key not in eligible_pairs or key in seen:
            continue
        seen.add(key)
        created = _parse_iso(assignment.get("created_date_time")) or now
        findings.append(
            _build_finding(
                finding_type="pim_eligible_and_active",
                principal_id=principal_id,
                principal_display_name=assignment.get("principal_display_name", ""),
                principal_type=assignment.get("principal_type", ""),
                role_definition_name=role,
                scope=assignment.get("scope", ""),
                detected_at=now,
                age_hours=_hours_between(now, created),
            )
        )
    return findings


def _detect_pim_absent(
    pim_configured: bool, now: datetime
) -> list[dict[str, Any]]:
    if pim_configured:
        return []
    return [
        _build_finding(
            finding_type="pim_absent",
            principal_id="",
            principal_display_name="Tenant",
            principal_type="Tenant",
            role_definition_name="All privileged roles",
            scope="/",
            detected_at=now,
            age_hours=0.0,
        )
    ]


# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------


def _compute_event_delay(
    current_snapshot: dict[str, Any], now: datetime
) -> tuple[bool, Optional[float]]:
    """Estimate Graph audit-log lag using the freshest assignment timestamp.

    Without a dedicated audit log query, we use the most recent
    ``created_date_time`` across RBAC assignments as a coarse proxy. A gap
    larger than two hours is flagged so the Data Quality notice can disclose
    that recent changes may not yet be visible.
    """

    timestamps: list[datetime] = []
    for item in current_snapshot.get("graph_rbac_assignments", []) or []:
        ts = _parse_iso(item.get("created_date_time"))
        if ts:
            timestamps.append(ts)
    for item in current_snapshot.get("arm_rbac_assignments", []) or []:
        ts = _parse_iso(item.get("created_on"))
        if ts:
            timestamps.append(ts)

    if not timestamps:
        return False, None

    most_recent = max(timestamps)
    lag_hours = _hours_between(now, most_recent)
    if lag_hours > 2.0:
        return True, round(lag_hours, 2)
    return False, round(lag_hours, 2)


def _compute_signal_conflicts(
    findings: list[dict[str, Any]], current_pim: list[dict[str, Any]]
) -> int:
    """Count cases where a role is removed in RBAC but still active in PIM."""

    active_pim = {
        (a.get("principal_id", ""), (a.get("role_definition_name") or "").lower())
        for a in current_pim
        if (a.get("assignment_type") or "").lower() == "activated"
    }
    if not active_pim:
        return 0

    conflicts = 0
    for finding in findings:
        if finding["finding_type"] != "rbac_removed":
            continue
        key = (
            finding["principal_id"],
            (finding["role_definition_name"] or "").lower(),
        )
        if key in active_pim:
            conflicts += 1
    return conflicts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_diff(
    current_snapshot: dict[str, Any],
    previous_snapshot: Optional[dict[str, Any]],
    preflight: PreflightResult,
) -> tuple[DiffResult, DataQuality]:
    """Compute findings and data-quality metadata for the report."""

    now = _now_utc()

    pim_configured = bool(current_snapshot.get("is_pim_configured")) and (
        preflight.pim_configured
    )
    has_arm = bool(current_snapshot.get("arm_rbac_assignments"))
    arm_data_available = preflight.subscription_accessible

    current_rbac = current_snapshot.get("graph_rbac_assignments", []) or []
    current_pim = current_snapshot.get("pim_activations", []) or []
    current_arm = current_snapshot.get("arm_rbac_assignments", []) or []
    previous_rbac = (
        (previous_snapshot or {}).get("graph_rbac_assignments", []) or []
    )
    previous_pim = (previous_snapshot or {}).get("pim_activations", []) or []

    if previous_snapshot is None:
        logger.info("No previous snapshot found; running in baseline mode.")
        delay_detected, delay_hours = _compute_event_delay(current_snapshot, now)
        data_quality = DataQuality(
            pim_data_available=pim_configured,
            arm_data_available=arm_data_available or has_arm,
            signal_conflict_count=0,
            event_delay_detected=delay_detected,
            event_delay_hours=delay_hours,
        )
        return (
            DiffResult(
                findings=[],
                is_baseline_run=True,
                current_snapshot_timestamp=current_snapshot.get("timestamp"),
                previous_snapshot_timestamp=None,
            ),
            data_quality,
        )

    findings: list[dict[str, Any]] = []
    findings.extend(_detect_rbac_changes(current_rbac, previous_rbac, now))
    findings.extend(_detect_orphaned(current_rbac, now))
    findings.extend(
        _detect_pim_bypass(current_rbac, current_arm, pim_configured, now)
    )
    findings.extend(
        _detect_service_principal_elevated(current_rbac, current_arm, now)
    )

    pim_findings, _ = _detect_pim_findings(
        current_pim, previous_pim, pim_configured, now
    )
    findings.extend(pim_findings)
    findings.extend(
        _detect_eligible_and_active(current_pim, current_rbac, pim_configured, now)
    )
    findings.extend(_detect_pim_absent(pim_configured, now))

    signal_conflict_count = _compute_signal_conflicts(findings, current_pim)
    delay_detected, delay_hours = _compute_event_delay(current_snapshot, now)

    data_quality = DataQuality(
        pim_data_available=pim_configured,
        arm_data_available=arm_data_available or has_arm,
        signal_conflict_count=signal_conflict_count,
        event_delay_detected=delay_detected,
        event_delay_hours=delay_hours,
    )

    diff = DiffResult(
        findings=findings,
        is_baseline_run=False,
        current_snapshot_timestamp=current_snapshot.get("timestamp"),
        previous_snapshot_timestamp=(previous_snapshot or {}).get("timestamp"),
    )
    return diff, data_quality
