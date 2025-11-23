"""Security helpers for validating user-controlled input."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Tuple


_DANGEROUS_PATTERNS = re.compile(r"[;&`]|\$\(|\|\||\n|\r|\>\>?")


def validate_scan_target(target: str, max_length: int = 512) -> Tuple[bool, str | None]:
    if not target or not target.strip():
        return False, "Target is required."

    candidate = target.strip()
    if len(candidate) > max_length:
        return False, "Target value is too long."

    if _DANGEROUS_PATTERNS.search(candidate):
        return False, "Target contains potentially dangerous characters."

    return True, None


def validate_interface_name(interface: str, allow_empty: bool = False) -> Tuple[bool, str | None]:
    if not interface:
        return (allow_empty, None if allow_empty else "Interface name is required.")

    if len(interface) > 64:
        return False, "Interface name is too long."

    if not re.match(r"^[a-zA-Z0-9._:-]+$", interface):
        return False, "Interface name contains invalid characters."

    return True, None


def enforce_path_within(base_dir: Path, candidate: Path) -> Path:
    resolved_base = base_dir.resolve()
    resolved_candidate = candidate.expanduser().resolve()
    if not str(resolved_candidate).startswith(str(resolved_base)):
        raise ValueError(f"Path must reside within {resolved_base}")
    return resolved_candidate


def clamp_text(value: str, max_length: int = 5000) -> str:
    return value[:max_length]


def validate_string_length(value: str, max_length: int, field: str) -> Tuple[bool, str | None]:
    if len(value) > max_length:
        return False, f"{field} is too long."
    return True, None


__all__ = [
    "clamp_text",
    "enforce_path_within",
    "validate_interface_name",
    "validate_scan_target",
    "validate_string_length",
]
