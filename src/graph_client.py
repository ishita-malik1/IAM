"""Microsoft Graph data collection.

Pulls Entra ID directory role assignments and PIM activation instances and
returns them as the lightweight, normalized dictionaries that the snapshot
schema expects. The two public functions are :func:`fetch_graph_rbac` and
:func:`fetch_pim_activations`.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Iterable, Optional

import requests

from src.auth import get_graph_token

logger = logging.getLogger(__name__)

# Microsoft Graph permits only a single ``$expand`` clause per request on the
# roleManagement endpoints. We expand ``principal`` (which gives us the
# display name and odata type we need for orphan and service-principal
# detection) and resolve role definitions via a separate one-shot fetch that
# is cached for the lifetime of the process.
_RBAC_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/"
    "roleAssignments?$expand=principal"
)
_PIM_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/"
    "roleAssignmentScheduleInstances?$expand=principal"
)
_ROLE_DEFINITIONS_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    "?$select=id,displayName,templateId"
)

_TIMEOUT_SECONDS = 60
_MAX_RETRIES = 3

_role_definition_cache: Optional[dict[str, str]] = None


class GraphPermissionError(PermissionError):
    """Raised on a 403 from Microsoft Graph.

    The message identifies the missing scope so it can be surfaced to the
    operator and so :func:`run_preflight` does not need to re-execute.
    """


def _auth_header() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Accept": "application/json",
    }


def _request_with_retries(url: str) -> dict[str, Any]:
    """GET ``url`` with exponential backoff on 429 and transient network errors.

    A ``Retry-After`` header is honored when present. Otherwise we back off
    1, 2, 4 seconds with a small random jitter.
    """

    attempt = 0
    while True:
        try:
            response = requests.get(
                url, headers=_auth_header(), timeout=_TIMEOUT_SECONDS
            )
        except requests.RequestException as exc:
            if attempt >= _MAX_RETRIES:
                raise
            wait = (2 ** attempt) + random.uniform(0, 0.5)
            logger.warning(
                "Network error talking to Graph (%s); retrying in %.1fs...",
                exc,
                wait,
            )
            time.sleep(wait)
            attempt += 1
            continue

        if response.status_code == 200:
            return response.json()

        if response.status_code == 403:
            raise GraphPermissionError(
                f"Graph returned 403 for {url}. Missing one of "
                "Directory.Read.All or RoleManagement.Read.Directory "
                "application permissions (admin consent required)."
            )

        if response.status_code == 429:
            if attempt >= _MAX_RETRIES:
                raise RuntimeError(
                    f"Graph rate limit not cleared after {_MAX_RETRIES} retries"
                )
            retry_after = response.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else (2 ** attempt)
            except ValueError:
                wait = 2 ** attempt
            wait += random.uniform(0, 0.5)
            logger.warning(
                "Graph rate limit hit; backing off for %.1fs (attempt %d/%d)",
                wait,
                attempt + 1,
                _MAX_RETRIES,
            )
            time.sleep(wait)
            attempt += 1
            continue

        if 500 <= response.status_code < 600 and attempt < _MAX_RETRIES:
            wait = (2 ** attempt) + random.uniform(0, 0.5)
            logger.warning(
                "Graph returned %s; retrying in %.1fs",
                response.status_code,
                wait,
            )
            time.sleep(wait)
            attempt += 1
            continue

        raise RuntimeError(
            f"Graph request to {url} failed: HTTP {response.status_code} "
            f"{response.text[:300]}"
        )


def _paginate(start_url: str) -> Iterable[dict[str, Any]]:
    """Yield every ``value`` element across all ``@odata.nextLink`` pages."""

    next_url: Optional[str] = start_url
    while next_url:
        page = _request_with_retries(next_url)
        for item in page.get("value", []) or []:
            yield item
        next_url = page.get("@odata.nextLink")


def _principal_type(principal: Optional[dict[str, Any]]) -> str:
    if not principal:
        return "Unknown"
    odata_type = (principal.get("@odata.type") or "").lower()
    if "serviceprincipal" in odata_type:
        return "ServicePrincipal"
    if "group" in odata_type:
        return "Group"
    if "user" in odata_type:
        return "User"
    return principal.get("principalType") or "Unknown"


def _principal_display(principal: Optional[dict[str, Any]], principal_id: str) -> str:
    if principal:
        name = principal.get("displayName")
        if name:
            return name
    return principal_id or "Unknown principal"


def _role_definitions() -> dict[str, str]:
    """Return a ``{role_definition_id: displayName}`` map.

    The result is cached in module scope so we issue at most one request per
    process. The map is keyed both by the GUID ``id`` and the ``templateId``
    (built-in role template) because assignments reference the former and
    some downstream tooling/data references the latter.
    """

    global _role_definition_cache
    if _role_definition_cache is not None:
        return _role_definition_cache

    logger.debug("Fetching Graph role definitions for name resolution...")
    mapping: dict[str, str] = {}
    try:
        for item in _paginate(_ROLE_DEFINITIONS_URL):
            display = item.get("displayName") or ""
            if not display:
                continue
            role_id = item.get("id") or ""
            template_id = item.get("templateId") or ""
            if role_id:
                mapping[role_id] = display
            if template_id and template_id not in mapping:
                mapping[template_id] = display
    except GraphPermissionError:
        logger.warning(
            "Role definitions endpoint denied access; role names will fall "
            "back to their IDs."
        )

    _role_definition_cache = mapping
    logger.debug("Cached %d role definition names.", len(mapping))
    return mapping


def _resolve_role_name(role_definition_id: str) -> str:
    if not role_definition_id:
        return "Unknown role"
    return _role_definitions().get(role_definition_id, role_definition_id)


def _normalize_rbac(item: dict[str, Any]) -> dict[str, Any]:
    principal = item.get("principal")
    principal_id = item.get("principalId") or (principal or {}).get("id") or ""
    role_definition_id = item.get("roleDefinitionId") or ""
    return {
        "id": item.get("id") or "",
        "principal_id": principal_id,
        "principal_display_name": _principal_display(principal, principal_id),
        "principal_type": _principal_type(principal),
        "role_definition_name": _resolve_role_name(role_definition_id),
        "scope": item.get("directoryScopeId") or "/",
        "created_date_time": item.get("createdDateTime"),
        "is_pim_managed": False,
    }


def _normalize_pim(item: dict[str, Any]) -> dict[str, Any]:
    principal = item.get("principal")
    principal_id = item.get("principalId") or (principal or {}).get("id") or ""
    role_definition_id = item.get("roleDefinitionId") or ""
    schedule_info = item.get("scheduleInfo") or {}
    expiration = schedule_info.get("expiration") or {}
    end_date_time = item.get("endDateTime") or expiration.get("endDateTime")
    return {
        "id": item.get("id") or "",
        "principal_id": principal_id,
        "principal_display_name": _principal_display(principal, principal_id),
        "principal_type": _principal_type(principal),
        "role_definition_name": _resolve_role_name(role_definition_id),
        "scope": item.get("directoryScopeId") or "/",
        "start_date_time": item.get("startDateTime")
        or schedule_info.get("startDateTime")
        or "",
        "end_date_time": end_date_time,
        "justification": item.get("justification"),
        "assignment_type": item.get("assignmentType") or "Activated",
    }


def fetch_graph_rbac() -> list[dict[str, Any]]:
    """Return every Entra ID directory role assignment, paginated and normalized."""

    logger.info("Fetching Graph directory role assignments...")
    items = [_normalize_rbac(raw) for raw in _paginate(_RBAC_URL)]
    logger.info("Fetched %d Graph RBAC assignments.", len(items))
    return items


def fetch_pim_activations() -> list[dict[str, Any]]:
    """Return every PIM role assignment schedule instance, normalized."""

    logger.info("Fetching PIM activation schedule instances...")
    try:
        items = [_normalize_pim(raw) for raw in _paginate(_PIM_URL)]
    except GraphPermissionError:
        logger.warning(
            "PIM endpoint denied access; returning empty activation list."
        )
        return []
    logger.info("Fetched %d PIM activations.", len(items))
    return items
