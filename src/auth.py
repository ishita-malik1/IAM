"""Authentication helpers for Microsoft Graph and Azure Resource Manager.

Both ``get_graph_token`` and ``get_arm_token`` acquire access tokens using the
OAuth 2.0 client credentials flow via :mod:`msal`. Tokens are cached in process
memory and only re-acquired when within 60 seconds of expiry.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

import msal

from src.config import (
    require_azure_client_id,
    require_azure_client_secret,
    require_azure_tenant_id,
)

logger = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"

_REFRESH_BUFFER_SECONDS = 60


class AuthenticationError(Exception):
    """Raised when MSAL fails to acquire a token.

    The MSAL error code and human-readable description are included in the
    exception message so callers can surface them in the preflight check or
    top-level run output.
    """


@dataclass
class _CachedToken:
    """Lightweight container for an access token and its absolute expiry time."""

    access_token: str
    expires_at: float  # epoch seconds


class _TokenManager:
    """Holds a single MSAL confidential client and per-scope token caches.

    The MSAL ``ConfidentialClientApplication`` already maintains its own cache,
    but we layer a tiny in-memory expiry tracker on top so we never make a
    network call on the hot path while the existing token is valid for at
    least one more minute.
    """

    def __init__(self) -> None:
        self._app: Optional[msal.ConfidentialClientApplication] = None
        self._tokens: dict[str, _CachedToken] = {}
        self._lock = threading.Lock()

    def _ensure_app(self) -> msal.ConfidentialClientApplication:
        if self._app is not None:
            return self._app

        try:
            tenant_id = require_azure_tenant_id()
            client_id = require_azure_client_id()
            client_secret = require_azure_client_secret()
        except ValueError as exc:
            raise AuthenticationError(str(exc)) from exc

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )
        return self._app

    def acquire(self, scope: str) -> str:
        with self._lock:
            cached = self._tokens.get(scope)
            now = time.time()
            if cached and cached.expires_at - now > _REFRESH_BUFFER_SECONDS:
                return cached.access_token

            app = self._ensure_app()
            logger.debug("Acquiring fresh token for scope %s", scope)
            result = app.acquire_token_for_client(scopes=[scope])

            if not isinstance(result, dict) or "access_token" not in result:
                error = (result or {}).get("error", "unknown_error")
                description = (result or {}).get(
                    "error_description", "no description provided"
                )
                raise AuthenticationError(
                    f"Token acquisition failed for scope {scope!r}: "
                    f"{error} - {description}"
                )

            expires_in = int(result.get("expires_in", 0)) or 3600
            self._tokens[scope] = _CachedToken(
                access_token=result["access_token"],
                expires_at=now + expires_in,
            )
            return result["access_token"]


_manager = _TokenManager()


def get_graph_token() -> str:
    """Return a valid access token for Microsoft Graph."""

    return _manager.acquire(GRAPH_SCOPE)


def get_arm_token() -> str:
    """Return a valid access token for Azure Resource Manager."""

    return _manager.acquire(ARM_SCOPE)
