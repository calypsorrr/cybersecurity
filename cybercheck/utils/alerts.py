from __future__ import annotations

import json
from datetime import datetime, timedelta

try:  # pragma: no cover - Python <3.11 fallback
    from datetime import UTC
except ImportError:  # pragma: no cover - fallback
    from datetime import timezone as _tz

    UTC = _tz.utc
from typing import Dict, Iterable, Optional

from cybercheck.models.db import fetch_alerts, insert_alert, update_alert


class AlertPipeline:
    """Lightweight alert manager with acknowledgment and suppression support."""

    def __init__(self) -> None:
        self.default_suppression = timedelta(minutes=30)

    def emit(self, source: str, severity: str, message: str, metadata: Optional[Dict] = None) -> int:
        payload = json.dumps(metadata or {})
        return insert_alert(source=source, severity=severity, message=message, status="open", metadata=payload)

    def acknowledge(self, alert_id: int, user: str) -> None:
        update_alert(alert_id, status="acknowledged", acknowledged_by=user)

    def suppress(self, alert_id: int, minutes: int = 30) -> None:
        until = datetime.now(UTC) + timedelta(minutes=minutes)
        update_alert(alert_id, status="suppressed", suppressed_until=until.isoformat())

    def list_recent(self, limit: int = 50):
        return fetch_alerts(limit=limit)


alert_pipeline = AlertPipeline()
