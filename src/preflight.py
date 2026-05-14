"""Preflight validation: confirm permissions and reachability before any pull.

The preflight check is intentionally cheap. It issues at most three small
``GET`` requests and never paginates. Its job is to fail fast with an
actionable error if the app registration is missing a permission, and to give
the diff engine enough information to surface PIM or ARM gaps as findings
rather than crashing the run.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

import requests

from src.auth import AuthenticationError, get_arm_token, get_graph_token
from src.subscription_util import normalize_subscription_id

logger = logging.getLogger(__name__)

_GRAPH_ORG_URL = "https://graph.microsoft.com/v1.0/organization"
_GRAPH_PIM_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/"
    "roleAssignmentScheduleInstances?$top=1"
)

_TIMEOUT_SECONDS = 30


class PreflightError(Exception):
    """Raised when preflight detects a fatal configuration issue."""


@dataclass
class PreflightResult:
    """Outcome of preflight validation.

    Attributes
    ----------
    graph_accessible:
        ``True`` if the directory ``/organization`` endpoint returned 200.
    arm_accessible:
        ``True`` if a token for ARM was acquired and the subscription endpoint
        returned 200. Always ``False`` when no subscription is configured.
    pim_configured:
        ``True`` if ``roleAssignmentScheduleInstances`` returned a 200. A 404 or
        empty response is treated as PIM not being configured.
    subscription_accessible:
        ``True`` if ``AZURE_SUBSCRIPTION_ID`` is set and the subscription GET
        succeeded.
    graph_error / arm_error:
        Human-readable description of the failure, if any.
    """

    graph_accessible: bool
    arm_accessible: bool
    pim_configured: bool
    subscription_accessible: bool
    graph_error: Optional[str]
    arm_error: Optional[str]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _check_graph() -> tuple[bool, Optional[str]]:
    try:
        token = get_graph_token()
    except AuthenticationError as exc:
        return False, f"Graph token acquisition failed: {exc}"

    try:
        response = requests.get(
            _GRAPH_ORG_URL, headers=_auth_header(token), timeout=_TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:
        return False, f"Graph organization endpoint unreachable: {exc}"

    if response.status_code == 200:
        return True, None
    if response.status_code in (401, 403):
        return False, (
            "Graph API rejected the app registration "
            f"(HTTP {response.status_code}). Confirm Directory.Read.All "
            "application permission has been granted with admin consent."
        )
    return False, (
        f"Graph organization endpoint returned HTTP {response.status_code}: "
        f"{response.text[:200]}"
    )


def _check_pim() -> bool:
    try:
        token = get_graph_token()
        response = requests.get(
            _GRAPH_PIM_URL, headers=_auth_header(token), timeout=_TIMEOUT_SECONDS
        )
    except (AuthenticationError, requests.RequestException) as exc:
        logger.warning("PIM probe failed; treating PIM as not configured: %s", exc)
        return False

    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    if response.status_code in (401, 403):
        logger.warning(
            "PIM endpoint rejected request (HTTP %s); treating PIM as not "
            "configured. Grant RoleManagement.Read.Directory to enable PIM "
            "coverage.",
            response.status_code,
        )
        return False
    logger.warning(
        "PIM endpoint returned unexpected HTTP %s; treating PIM as not "
        "configured.",
        response.status_code,
    )
    return False


def _check_arm(subscription_id_raw: str) -> tuple[bool, bool, Optional[str]]:
    """Return ``(arm_accessible, subscription_accessible, error)``."""

    sub_id = normalize_subscription_id(subscription_id_raw)
    if not sub_id:
        return False, False, (
            "AZURE_SUBSCRIPTION_ID is set but is not a valid subscription GUID. "
            "Use only the GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) from "
            "Azure portal > Subscriptions, with no quotes or label text."
        )

    try:
        token = get_arm_token()
    except AuthenticationError as exc:
        return False, False, f"ARM token acquisition failed: {exc}"

    base = f"https://management.azure.com/subscriptions/{sub_id}"
    try:
        response = requests.get(
            base,
            headers=_auth_header(token),
            params={"api-version": "2020-01-01"},
            timeout=_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return False, False, f"ARM subscription endpoint unreachable: {exc}"

    if response.status_code == 200:
        return True, True, None
    if response.status_code in (401, 403):
        return False, False, (
            "ARM rejected the request "
            f"(HTTP {response.status_code}). Grant the service principal at "
            "least the Reader role on the subscription."
        )
    if response.status_code == 404:
        return False, False, (
            f"Subscription {sub_id} not found. Verify "
            "AZURE_SUBSCRIPTION_ID is correct."
        )
    if response.status_code == 400:
        body = (response.text or "")[:280]
        return False, False, (
            "ARM returned HTTP 400 (often MissingApiVersionParameter when the "
            "subscription id in .env is malformed—quotes, spaces, or pasted "
            "text without a GUID). Parsed id: "
            f"{sub_id!r}. Response: {body}"
        )
    return False, False, (
        f"ARM subscription endpoint returned HTTP {response.status_code}: "
        f"{response.text[:200]}"
    )


def run_preflight() -> PreflightResult:
    """Execute the preflight checks and return a :class:`PreflightResult`.

    Raises
    ------
    PreflightError
        If Graph itself is not reachable. PIM and ARM gaps do not raise; they
        are reported via the returned dataclass so the diff engine can decide
        how to handle them.
    """

    logger.info("Running preflight checks...")
    graph_accessible, graph_error = _check_graph()
    if not graph_accessible:
        raise PreflightError(
            graph_error
            or "Microsoft Graph is not accessible with the configured app "
            "registration."
        )

    pim_configured = _check_pim()

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    if subscription_id:
        arm_accessible, subscription_accessible, arm_error = _check_arm(
            subscription_id
        )
    else:
        arm_accessible = False
        subscription_accessible = False
        arm_error = None
        logger.info(
            "AZURE_SUBSCRIPTION_ID is not set; ARM RBAC collection will be "
            "skipped."
        )

    result = PreflightResult(
        graph_accessible=graph_accessible,
        arm_accessible=arm_accessible,
        pim_configured=pim_configured,
        subscription_accessible=subscription_accessible,
        graph_error=graph_error,
        arm_error=arm_error,
    )
    logger.info(
        "Preflight validation passed. PIM: %s. ARM: %s.",
        "configured" if pim_configured else "not configured",
        "configured" if subscription_accessible else "not configured",
    )
    return result
