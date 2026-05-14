"""Azure Resource Manager RBAC collection.

Pulls role assignments at subscription scope and resolves each
``roleDefinitionId`` to a human-readable role name via a per-session cache.
If ``AZURE_SUBSCRIPTION_ID`` is empty the client returns an empty list without
error so the rest of the pipeline can run unchanged.
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Any, Iterable, Optional

import requests

from src.auth import get_arm_token
from src.subscription_util import normalize_subscription_id

logger = logging.getLogger(__name__)

_ASSIGNMENTS_API_VERSION = "2022-04-01"
_DEFINITIONS_API_VERSION = "2022-04-01"

_TIMEOUT_SECONDS = 60
_MAX_RETRIES = 3


def _auth_header() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {get_arm_token()}",
        "Accept": "application/json",
    }


def _request_with_retries(url: str) -> dict[str, Any]:
    """GET ``url`` with the same backoff policy used by the Graph client."""

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
                "Network error talking to ARM (%s); retrying in %.1fs...",
                exc,
                wait,
            )
            time.sleep(wait)
            attempt += 1
            continue

        if response.status_code == 200:
            return response.json()

        if response.status_code == 403:
            raise PermissionError(
                f"ARM returned 403 for {url}. The service principal needs at "
                "least the Reader role on the subscription."
            )

        if response.status_code == 429:
            if attempt >= _MAX_RETRIES:
                raise RuntimeError(
                    f"ARM rate limit not cleared after {_MAX_RETRIES} retries"
                )
            retry_after = response.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else (2 ** attempt)
            except ValueError:
                wait = 2 ** attempt
            wait += random.uniform(0, 0.5)
            logger.warning(
                "ARM rate limit hit; backing off for %.1fs (attempt %d/%d)",
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
                "ARM returned %s; retrying in %.1fs",
                response.status_code,
                wait,
            )
            time.sleep(wait)
            attempt += 1
            continue

        raise RuntimeError(
            f"ARM request to {url} failed: HTTP {response.status_code} "
            f"{response.text[:300]}"
        )


def _paginate(start_url: str) -> Iterable[dict[str, Any]]:
    next_url: Optional[str] = start_url
    while next_url:
        page = _request_with_retries(next_url)
        for item in page.get("value", []) or []:
            yield item
        next_url = page.get("nextLink")


class _RoleDefinitionCache:
    """Resolve role definition IDs to display names, once per session."""

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}

    def resolve(self, role_definition_id: str) -> str:
        if not role_definition_id:
            return "Unknown role"
        if role_definition_id in self._cache:
            return self._cache[role_definition_id]
        url = (
            f"https://management.azure.com{role_definition_id}"
            f"?api-version={_DEFINITIONS_API_VERSION}"
        )
        try:
            payload = _request_with_retries(url)
        except (PermissionError, RuntimeError) as exc:
            logger.warning(
                "Failed to resolve role definition %s: %s", role_definition_id, exc
            )
            self._cache[role_definition_id] = "Unknown role"
            return "Unknown role"

        properties = payload.get("properties") or {}
        name = properties.get("roleName") or "Unknown role"
        self._cache[role_definition_id] = name
        return name


def _normalize(item: dict[str, Any], cache: _RoleDefinitionCache) -> dict[str, Any]:
    properties = item.get("properties") or {}
    role_definition_id = properties.get("roleDefinitionId") or ""
    return {
        "id": item.get("id") or "",
        "principal_id": properties.get("principalId") or "",
        "principal_type": properties.get("principalType") or "Unknown",
        "role_definition_name": cache.resolve(role_definition_id),
        "scope": properties.get("scope") or "",
        "created_on": properties.get("createdOn"),
    }


def fetch_arm_rbac() -> list[dict[str, Any]]:
    """Return every ARM RBAC assignment at subscription scope, or an empty list."""

    subscription_id = normalize_subscription_id(
        os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    )
    if not subscription_id:
        logger.info("AZURE_SUBSCRIPTION_ID is empty; skipping ARM collection.")
        return []

    logger.info(
        "Fetching ARM RBAC assignments for subscription %s...", subscription_id
    )
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Authorization/roleAssignments"
        f"?api-version={_ASSIGNMENTS_API_VERSION}"
    )
    cache = _RoleDefinitionCache()
    try:
        items = [_normalize(raw, cache) for raw in _paginate(url)]
    except PermissionError as exc:
        logger.warning("ARM permission denied; returning empty list: %s", exc)
        return []
    logger.info("Fetched %d ARM RBAC assignments.", len(items))
    return items
