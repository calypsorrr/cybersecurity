"""Utility helpers for exporting run history."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable, Mapping

try:  # pragma: no cover - Py<3.11 fallback
    from datetime import UTC
except ImportError:  # pragma: no cover - Py<3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

from cybercheck.models.db import fetch_last_runs


def _normalize_rows(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def generate_json_report(limit: int = 100) -> str:
    """Return the latest run metadata as a JSON string.

    The helper is used by the download endpoint and CLI utilities. It now lives
    in the ``cybercheck`` package (previously it imported ``models`` as a loose
    module) so any consumer using ``python -m cybercheck.utils.reporting`` just
    works regardless of the working directory.
    """

    limit = max(1, limit)
    rows = fetch_last_runs(limit)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "runs": _normalize_rows(rows),
    }
    return json.dumps(payload, indent=2)
