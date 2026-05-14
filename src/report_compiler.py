"""HTML report assembly.

Renders ``templates/report.html.j2`` with all the data the manager needs to
read and act on the digest. The output is a self-contained file written to
``reports/iam_digest_{ISO_date}.html``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.diff_engine import DataQuality, DiffResult
from src.preflight import PreflightResult

logger = logging.getLogger(__name__)


REPORTS_DIR = Path("reports")
TEMPLATES_DIR = Path("templates")

_CHANGE_TYPE_LABELS: dict[str, str] = {
    "rbac_new": "New Assignment",
    "rbac_removed": "Assignment Removed",
    "rbac_escalated": "Scope Escalated",
    "rbac_stale": "Standing Role Past Review Threshold",
    "rbac_orphaned": "Orphaned Access",
    "rbac_pim_bypass": "PIM Bypass",
    "pim_stale": "Stale PIM Activation",
    "pim_no_justification": "Unjustified Activation",
    "pim_repeated": "Repeated Activations",
    "pim_eligible_and_active": "Duplicate Assignment",
    "pim_absent": "PIM Not Configured",
    "service_principal_elevated": "Elevated Service Principal",
}


def _format_datetime(value: Optional[str]) -> str:
    """Render an ISO 8601 string as ``15 Jan 2025, 10:42 UTC``."""

    if not value:
        return ""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%d %b %Y, %H:%M UTC")


def _format_age(hours: Optional[float]) -> str:
    if hours is None:
        return ""
    hours = float(hours)
    if hours < 1:
        minutes = int(round(hours * 60))
        return f"{minutes} min"
    if hours < 48:
        return f"{hours:.1f} h"
    days = hours / 24.0
    return f"{days:.1f} d"


def _change_type_label(finding_type: str) -> str:
    return _CHANGE_TYPE_LABELS.get(finding_type, finding_type)


def _principal_label(finding: dict[str, Any]) -> str:
    name = finding.get("principal_display_name") or finding.get("principal_id") or "Unknown"
    if (finding.get("principal_type") or "").lower() == "serviceprincipal":
        return f"{name} (Service Principal)"
    return name


def _overall_risk(findings: list[dict[str, Any]]) -> str:
    severities = {(f.get("severity") or "low").lower() for f in findings}
    if "high" in severities:
        return "HIGH"
    if "medium" in severities:
        return "MEDIUM"
    return "LOW"


def _critical_summary_sentence(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No access drift detected in this review period."
    top = next(
        (f for f in findings if (f.get("severity") or "").lower() == "high"),
        None,
    ) or findings[0]
    label = _change_type_label(top["finding_type"])
    principal = _principal_label(top)
    role = top.get("role_definition_name") or "an unspecified role"
    return (
        f"The most critical finding is a {label.lower()} affecting "
        f"{principal} in {role}."
    )


def _data_quality_notices(
    quality: DataQuality, preflight: PreflightResult
) -> list[str]:
    """Return a list of human-readable notices for the Data Quality block."""

    notices: list[str] = []
    if not quality.pim_data_available:
        notices.append(
            "PIM data was not available for this scan. Findings related to "
            "just-in-time access (stale activations, eligible-vs-active "
            "duplicates, repeated activations) will not appear in this "
            "report."
        )
    if not quality.arm_data_available:
        notices.append(
            "Azure Resource Manager RBAC was not collected. This report "
            "covers Entra ID directory roles only and will not surface "
            "subscription- or resource-level role assignments."
        )
    if quality.signal_conflict_count:
        notices.append(
            f"{quality.signal_conflict_count} signal conflict(s) detected: "
            "role(s) appear removed in RBAC but are still active in the PIM "
            "log. Both findings are surfaced independently in this report so "
            "you can reconcile them."
        )
    if quality.event_delay_detected and quality.event_delay_hours is not None:
        notices.append(
            "Assignment timestamps in this scan suggest directory data may be "
            f"about {quality.event_delay_hours} hours stale relative to scan "
            "time (heuristic based on the newest createdDateTime / createdOn "
            "values collected, not the Graph audit log API). Very recent "
            "changes may appear on the next run."
        )
    if preflight.graph_error:
        notices.append(f"Graph note: {preflight.graph_error}")
    if preflight.arm_error:
        notices.append(f"ARM note: {preflight.arm_error}")
    return notices


def _build_environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_report(
    *,
    diff: DiffResult,
    quality: DataQuality,
    preflight: PreflightResult,
    snapshot_metadata: dict[str, Any],
) -> Path:
    """Render the template and return the path to the written HTML file."""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    findings = list(diff.findings)
    overall_risk = _overall_risk(findings)
    high_findings = [f for f in findings if f["severity"] == "high"]
    medium_findings = [f for f in findings if f["severity"] == "medium"]
    low_findings = [f for f in findings if f["severity"] == "low"]

    actionable = [f for f in findings if f["severity"] in ("high", "medium")]
    actionable.sort(key=lambda f: f.get("priority_rank") or 9_999)

    chronological = sorted(
        findings, key=lambda f: f.get("detected_at") or "", reverse=True
    )

    full_audit = sorted(findings, key=lambda f: f.get("priority_rank") or 9_999)

    top_three = [f for f in actionable if f.get("priority_rank") and f["priority_rank"] <= 3]
    top_three.sort(key=lambda f: f["priority_rank"])

    cadence_days = os.environ.get("REPORT_CADENCE_DAYS", "7")

    context = {
        "generated_at": _format_datetime(
            snapshot_metadata.get("timestamp")
        )
        or _format_datetime(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        "previous_snapshot_timestamp": _format_datetime(
            diff.previous_snapshot_timestamp
        ),
        "is_baseline_run": diff.is_baseline_run,
        "overall_risk": overall_risk,
        "totals": {
            "all": len(findings),
            "high": len(high_findings),
            "medium": len(medium_findings),
            "low": len(low_findings),
            "actions_required": len(high_findings) + len(medium_findings),
        },
        "critical_summary": _critical_summary_sentence(findings),
        "top_three": top_three,
        "actionable": actionable,
        "low_findings": low_findings,
        "chronological": chronological,
        "full_audit": full_audit,
        "data_quality": asdict(quality),
        "data_quality_notices": _data_quality_notices(quality, preflight),
        "preflight": asdict(preflight),
        "cadence_days": cadence_days,
        "snapshot_id": snapshot_metadata.get("snapshot_id", ""),
        # helpers exposed to template
        "fmt_datetime": _format_datetime,
        "fmt_age": _format_age,
        "change_type_label": _change_type_label,
        "principal_label": _principal_label,
    }

    env = _build_environment()
    template = env.get_template("report.html.j2")
    html = template.render(**context)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output_path = REPORTS_DIR / f"iam_digest_{today}.html"
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("Report written to: %s", output_path.as_posix())
    return output_path
