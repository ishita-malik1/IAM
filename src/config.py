"""Centralized reading of environment-driven thresholds."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def stale_pim_threshold_hours() -> float:
    """Hours after which an active PIM assignment is considered stale."""

    raw = os.environ.get("STALE_PIM_THRESHOLD_HOURS", "24")
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "STALE_PIM_THRESHOLD_HOURS=%r is not a number; defaulting to 24.", raw
        )
        return 24.0
    if value <= 0:
        return 24.0
    return value


def stale_rbac_threshold_hours() -> float:
    """Hours a standing directory-role assignment may exist before review.

    Used for ``rbac_stale`` findings (tier-0 style roles) and for the
    ``rbac_new`` severity split (medium vs low) based on assignment age.
    """

    raw = os.environ.get("STALE_RBAC_THRESHOLD_HOURS", "48")
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "STALE_RBAC_THRESHOLD_HOURS=%r is not a number; defaulting to 48.",
            raw,
        )
        return 48.0
    if value <= 0:
        return 48.0
    return value
