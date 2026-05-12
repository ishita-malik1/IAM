"""Snapshot persistence: write and read JSON snapshot files.

Snapshots live in ``snapshots/snapshot_{ISO_timestamp}.json`` and conform to
the schema documented in the project README. Filenames use a UTC timestamp
with ``:`` characters replaced by ``-`` so they are valid on Windows file
systems while still sorting lexicographically.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

SNAPSHOTS_DIR = Path("snapshots")
_FILENAME_PATTERN = re.compile(r"^snapshot_.+\.json$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_snapshot(
    *,
    is_pim_configured: bool,
    graph_rbac_assignments: list[dict[str, Any]],
    pim_activations: list[dict[str, Any]],
    arm_rbac_assignments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compose a snapshot dictionary in the schema expected on disk."""

    return {
        "snapshot_id": str(uuid.uuid4()),
        "timestamp": _utc_now_iso(),
        "is_pim_configured": is_pim_configured,
        "graph_rbac_assignments": graph_rbac_assignments,
        "pim_activations": pim_activations,
        "arm_rbac_assignments": arm_rbac_assignments,
    }


def save_snapshot(data: dict[str, Any]) -> Path:
    """Write ``data`` to ``snapshots/snapshot_{ISO_timestamp}.json``.

    The timestamp in the filename is derived from ``data['timestamp']`` so the
    file name and content are always in sync. Returns the path of the written
    file.
    """

    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = data.get("timestamp") or _utc_now_iso()
    safe_timestamp = timestamp.replace(":", "-")
    path = SNAPSHOTS_DIR / f"snapshot_{safe_timestamp}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    logger.info("Snapshot written to %s", path)
    return path


def load_latest_snapshot() -> Optional[dict[str, Any]]:
    """Return the most recent snapshot dictionary, or ``None`` if there is none.

    Files are sorted by filename, which by construction is a lexicographically
    increasing UTC timestamp.
    """

    if not SNAPSHOTS_DIR.exists():
        return None

    candidates = sorted(
        (
            entry
            for entry in SNAPSHOTS_DIR.iterdir()
            if entry.is_file() and _FILENAME_PATTERN.match(entry.name)
        ),
        key=lambda p: p.name,
    )
    if not candidates:
        return None

    latest = candidates[-1]
    try:
        with latest.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "Latest snapshot %s is unreadable (%s); ignoring.", latest, exc
        )
        return None

    logger.info("Loaded previous snapshot: %s", latest.as_posix())
    return data


def latest_snapshot_path() -> Optional[Path]:
    """Return the path of the most recent snapshot, or ``None``."""

    if not SNAPSHOTS_DIR.exists():
        return None
    candidates = sorted(
        (
            entry
            for entry in SNAPSHOTS_DIR.iterdir()
            if entry.is_file() and _FILENAME_PATTERN.match(entry.name)
        ),
        key=lambda p: p.name,
    )
    return candidates[-1] if candidates else None


__all__ = [
    "SNAPSHOTS_DIR",
    "build_snapshot",
    "save_snapshot",
    "load_latest_snapshot",
    "latest_snapshot_path",
]


# Side-effect: make sure the import does not fail in environments that
# pre-create the directory; ``mkdir`` is invoked explicitly in ``save_snapshot``.
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
