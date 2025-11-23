"""Centralized logging configuration for the CyberCheck dashboard."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from cybercheck.config import BASE_DIR


_LOG_PATH = Path(BASE_DIR) / "logs" / "cybercheck.log"


def _configure_root(level: int = logging.INFO) -> None:
    log_dir = _LOG_PATH.parent
    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        _LOG_PATH, maxBytes=1_000_000, backupCount=5
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root = logging.getLogger("cybercheck")
    if root.handlers:
        return

    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


def get_logger(name: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """Return a module-specific logger with rotation enabled."""

    _configure_root(level=level)
    logger_name = "cybercheck" if not name else f"cybercheck.{name}"
    return logging.getLogger(logger_name)


__all__ = ["get_logger"]
