"""IAM Risk Digest entry point.

Run::

    python run_digest.py --run-now           # one-off
    python run_digest.py --schedule          # weekly scheduler
    python run_digest.py --run-now --verbose # DEBUG logging
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Optional

from dotenv import load_dotenv

logger = logging.getLogger("iam_risk_digest")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        stream=sys.stdout,
    )
    if verbose:
        logging.getLogger("urllib3").setLevel(logging.INFO)
        logging.getLogger("msal").setLevel(logging.INFO)
    else:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("msal").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def execute_digest() -> Optional[str]:
    """Run a single digest cycle. Returns the path to the generated report.

    Returns ``None`` if the run is aborted before report generation, but in
    practice failures raise instead so the top-level handler can surface a
    descriptive error message.
    """

    # Local imports keep ``--help`` cheap and isolate failures during preflight
    # debugging from import-time side effects.
    from src.preflight import run_preflight
    from src.graph_client import fetch_graph_rbac, fetch_pim_activations
    from src.arm_client import fetch_arm_rbac
    from src.snapshot import build_snapshot, load_latest_snapshot, save_snapshot
    from src.diff_engine import run_diff
    from src.risk_scorer import score_findings
    from src.priority_engine import prioritize
    from src.action_generator import generate_actions
    from src.report_compiler import render_report

    preflight_result = run_preflight()

    graph_rbac = fetch_graph_rbac()
    pim_activations = (
        fetch_pim_activations() if preflight_result.pim_configured else []
    )
    arm_rbac = fetch_arm_rbac() if preflight_result.subscription_accessible else []

    logger.info(
        "Pulled %d Graph RBAC assignments, %d PIM activations, %d ARM "
        "assignments.",
        len(graph_rbac),
        len(pim_activations),
        len(arm_rbac),
    )

    previous_snapshot = load_latest_snapshot()
    current_snapshot = build_snapshot(
        is_pim_configured=preflight_result.pim_configured,
        graph_rbac_assignments=graph_rbac,
        pim_activations=pim_activations,
        arm_rbac_assignments=arm_rbac,
    )
    save_snapshot(current_snapshot)

    diff_result, data_quality = run_diff(
        current_snapshot, previous_snapshot, preflight_result
    )

    logger.info(
        "Data quality: PIM %s, ARM %s, %d signal conflicts, "
        "event delay %s.",
        "available" if data_quality.pim_data_available else "not configured",
        "available" if data_quality.arm_data_available else "not configured",
        data_quality.signal_conflict_count,
        f"{data_quality.event_delay_hours}h" if data_quality.event_delay_detected else "not detected",
    )

    findings = score_findings(diff_result.findings)
    findings = prioritize(findings)
    findings = generate_actions(findings)
    diff_result.findings = findings

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    logger.info(
        "Diff complete: %d high, %d medium, %d low findings.",
        counts["high"],
        counts["medium"],
        counts["low"],
    )

    report_path = render_report(
        diff=diff_result,
        quality=data_quality,
        preflight=preflight_result,
        snapshot_metadata=current_snapshot,
    )

    actions_required = counts["high"] + counts["medium"]
    summary = (
        f"Summary: {len(findings)} findings | {counts['high']} HIGH | "
        f"{counts['medium']} MEDIUM | {counts['low']} LOW | "
        f"Actions required: {actions_required}"
    )
    print(f"Report written to: {report_path.as_posix()}")
    print(summary)
    return report_path.as_posix()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iam-risk-digest",
        description=(
            "Pull Microsoft Entra ID and ARM RBAC data, diff against the "
            "last snapshot, and produce a self-contained HTML report."
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--run-now",
        action="store_true",
        help="Run the digest pipeline once and exit.",
    )
    group.add_argument(
        "--schedule",
        action="store_true",
        help="Start the weekly scheduler in the foreground.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Set logging to DEBUG.",
    )
    return parser.parse_args(argv)


def _run_scheduled() -> None:
    """Block forever, executing the digest weekly via the ``schedule`` lib.

    Cadence is taken from ``REPORT_CADENCE_DAYS`` (default 7). The first run
    happens immediately so the operator gets feedback that the scheduler is
    healthy before the long sleep begins.
    """

    import schedule

    cadence_days = max(1, int(os.environ.get("REPORT_CADENCE_DAYS", "7") or 7))

    logger.info(
        "Starting scheduler: digest every %d day(s). Press Ctrl+C to stop.",
        cadence_days,
    )

    def _safe_run() -> None:
        try:
            execute_digest()
        except Exception as exc:  # noqa: BLE001 - top-level safety net
            logger.exception("Scheduled run failed: %s", exc)

    _safe_run()
    schedule.every(cadence_days).days.do(_safe_run)

    while True:
        schedule.run_pending()
        time.sleep(60)


def main(argv: Optional[list[str]] = None) -> int:
    load_dotenv(override=False)
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _configure_logging(args.verbose)

    if not (args.run_now or args.schedule):
        print(
            "Usage: python run_digest.py [--run-now | --schedule] [--verbose]\n"
            "\n"
            "  --run-now    Execute one digest cycle now and write a report.\n"
            "  --schedule   Run the digest on a recurring schedule.\n"
            "  --verbose    Enable DEBUG logging.\n"
        )
        return 0

    try:
        if args.run_now:
            execute_digest()
        elif args.schedule:
            _run_scheduled()
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        logger.exception("Digest run failed: %s", exc)
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
