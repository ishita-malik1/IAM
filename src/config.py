"""Centralized reading of environment-driven thresholds and Azure credentials."""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

_GUID = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

_PLACEHOLDER_MARKERS = (
    "your entra",
    "your tenant",
    "tenant id",
    "client id",
    "client secret",
    "subscription id",
    "leave blank",
    "optional",
)


def normalize_env_value(raw: str | None) -> str:
    """Strip whitespace, quotes, and accidental inline ``#`` comments.

    ``python-dotenv`` treats ``KEY=# comment`` (no space before ``#``) as the
  full value ``# comment``. This helper keeps only the part before ``#``.
    """

    if not raw:
        return ""
    value = raw.strip().strip("\ufeff")
    for q in ('"', "'", "`"):
        if len(value) >= 2 and value[0] == q and value[-1] == q:
            value = value[1:-1].strip()
            break
    if "#" in value:
        value = value.split("#", maxsplit=1)[0].strip()
    return value


def _looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in _PLACEHOLDER_MARKERS)


def require_azure_tenant_id() -> str:
    value = normalize_env_value(os.environ.get("AZURE_TENANT_ID"))
    if not value or _looks_like_placeholder(value) or not _GUID.match(value):
        raise ValueError(
            "AZURE_TENANT_ID must be your Entra tenant GUID only (no placeholder "
            "text, no comments on the same line). In .env use:\n"
            "  AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n"
            "Find it in Entra admin center > Microsoft Entra ID > Overview > "
            "Tenant ID."
        )
    return value


def require_azure_client_id() -> str:
    value = normalize_env_value(os.environ.get("AZURE_CLIENT_ID"))
    if not value or _looks_like_placeholder(value) or not _GUID.match(value):
        raise ValueError(
            "AZURE_CLIENT_ID must be your app registration (client) GUID. "
            "Put the value alone on the line in .env with no trailing comment."
        )
    return value


def require_azure_client_secret() -> str:
    value = normalize_env_value(os.environ.get("AZURE_CLIENT_SECRET"))
    if not value or _looks_like_placeholder(value):
        raise ValueError(
            "AZURE_CLIENT_SECRET must be set to the app registration client "
            "secret value (one line in .env, no placeholder text)."
        )
    return value


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
