"""Test helpers for CyberCheck."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the parent of the ``cybercheck`` package is importable when tests are
# executed from within the package directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PARENT = PROJECT_ROOT.parent
if str(PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_PARENT))
