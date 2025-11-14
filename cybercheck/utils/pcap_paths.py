from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from cybercheck.config import BASE_DIR

_DEFAULT_PCAP_DIR = Path(BASE_DIR) / "logs" / "ettercap_pcaps"
_DEFAULT_PCAP_DIR.mkdir(parents=True, exist_ok=True)


def _slugify(value: str | None) -> str:
    if not value:
        return "capture"
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "capture"


def resolve_pcap_output_path(user: str, requested_path: str | None = None) -> str:
    """Return an absolute PCAP path, creating parent directories as needed.

    If ``requested_path`` is provided it is respected (with user-relative segments
    resolved under the default capture directory). Otherwise a timestamped file
    is created beneath ``logs/ettercap_pcaps`` so sniffing sessions always have a
    valid capture destination.
    """

    if requested_path:
        path = Path(requested_path).expanduser()
        if not path.is_absolute():
            path = (_DEFAULT_PCAP_DIR / path).resolve()
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        path = _DEFAULT_PCAP_DIR / f"ettercap-{timestamp}-{_slugify(user)}.pcap"

    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)
