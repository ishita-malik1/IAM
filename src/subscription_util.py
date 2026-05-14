"""Normalize ``AZURE_SUBSCRIPTION_ID`` from environment / .env files."""

from __future__ import annotations

import re

_SUBSCRIPTION_GUID = re.compile(
    r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


def normalize_subscription_id(raw: str | None) -> str:
    """Return a bare subscription GUID suitable for ARM URLs.

    Accepts a plain GUID, a GUID wrapped in quotes, or a pasted Azure portal
    URL containing ``/subscriptions/{guid}``. Strips BOM and whitespace.

    If no GUID pattern is found, returns the trimmed string (caller may
    still get a 400 from ARM).
    """

    if not raw:
        return ""
    s = raw.strip().strip("\ufeff")
    for q in ('"', "'", "`"):
        if len(s) >= 2 and s[0] == q and s[-1] == q:
            s = s[1:-1].strip()
            break
    m = _SUBSCRIPTION_GUID.search(s)
    if m:
        return m.group(1).lower()
    s = s.split("?", maxsplit=1)[0].split("#", maxsplit=1)[0].strip()
    m = _SUBSCRIPTION_GUID.search(s)
    if m:
        return m.group(1).lower()
    return ""


def looks_like_subscription_guid(value: str) -> bool:
    """True if ``value`` is exactly one subscription-style GUID."""

    return bool(
        re.fullmatch(
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value.strip(),
        )
    )
