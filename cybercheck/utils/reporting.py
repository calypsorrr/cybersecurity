from __future__ import annotations

"""Compliance export helpers for dashboards and SIEM forwarding."""

from typing import Dict, List

from cybercheck.models.db import fetch_control_mappings, fetch_findings
from cybercheck.utils.threat_intel import enrich_blob


def build_control_report(limit: int = 50) -> Dict[str, List[Dict]]:
    controls = fetch_control_mappings()
    findings = fetch_findings(limit)

    enriched_findings: List[Dict] = []
    for row in findings:
        row_dict = dict(row)
        blob = " ".join(str(v or "") for v in row_dict.values())
        enriched_findings.append(
            {
                **row_dict,
                "threat_intel": enrich_blob(blob),
            }
        )

    return {
        "controls": [dict(c) for c in controls],
        "findings": [dict(f) for f in enriched_findings],
    }

