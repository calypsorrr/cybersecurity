from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

try:  # pragma: no cover - Python <3.11 fallback
    from datetime import UTC
except ImportError:  # pragma: no cover - fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

from cybercheck.config import BASE_DIR

_DEFAULT_PCAP_DIR = Path(BASE_DIR) / "logs" / "ettercap_pcaps"
_DEFAULT_PCAP_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_within_default_dir(path: Path) -> Path:
    """Return *path* when it resides under the capture directory.

    ``Path.resolve`` collapses any ``..`` segments, so this guard prevents
    directory traversal attacks that could otherwise trick the application into
    writing captures outside ``logs/ettercap_pcaps``. The check is intentionally
    strict: even absolute paths must live inside the default directory so that
    operators cannot accidentally target sensitive locations on disk from the
    web UI.
    """

    resolved = path.resolve()
    try:
        resolved.relative_to(_DEFAULT_PCAP_DIR)
    except ValueError as exc:  # pragma: no cover - defensive programming
        raise ValueError(
            f"PCAP output paths must stay within {_DEFAULT_PCAP_DIR}"  # noqa: TRY003
        ) from exc
    return resolved


def _slugify(value: str | None) -> str:
    if not value:
        return "capture"
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "capture"


def resolve_pcap_output_path(user: str, requested_path: str | None = None) -> str:
    """Return a sanitized absolute PCAP path.

    User-provided paths are always forced to live under the default capture
    directory. This prevents directory traversal tricks (for example passing
    ``../../etc/shadow``) that could otherwise overwrite arbitrary files on the
    host. When *requested_path* is empty we fall back to a timestamped file in
    ``logs/ettercap_pcaps``.
    """

    if requested_path:
        path = Path(requested_path).expanduser()
        if not path.is_absolute():
            path = _DEFAULT_PCAP_DIR / path
        sanitized = _ensure_within_default_dir(path)
    else:
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        generated = _DEFAULT_PCAP_DIR / f"ettercap-{timestamp}-{_slugify(user)}.pcap"
        sanitized = _ensure_within_default_dir(generated)

    sanitized.parent.mkdir(parents=True, exist_ok=True)
    return str(sanitized)
