from __future__ import annotations

"""Lightweight CVE enrichment helpers for offline use.

The helpers work without network access by using a compact in-memory
dataset (CVSS + EPSS-style likelihoods)."""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
import re


_CVE_HINTS = {
    "CVE-2023-34362": {"cvss": 9.8, "epss": 0.97, "product": "MOVEit Transfer"},
    "CVE-2024-3094": {"cvss": 10.0, "epss": 0.88, "product": "xz utils"},
    "CVE-2023-4863": {"cvss": 8.8, "epss": 0.61, "product": "libwebp"},
    "CVE-2022-22965": {"cvss": 9.8, "epss": 0.83, "product": "Spring Framework"},
}


@dataclass
class EnrichedCVE:
    cve: str
    cvss: float
    epss: float
    product: Optional[str]

    def as_dict(self) -> Dict[str, float | str | None]:
        return {"cve": self.cve, "cvss": self.cvss, "epss": self.epss, "product": self.product}


def extract_cves_from_text(blob: str) -> List[str]:
    pattern = r"CVE-\d{4}-\d{4,7}"
    return sorted(set(re.findall(pattern, blob)))


def enrich_cves(cve_ids: Iterable[str]) -> List[EnrichedCVE]:
    enriched: List[EnrichedCVE] = []
    for cve in cve_ids:
        meta = _CVE_HINTS.get(cve, {"cvss": 5.0, "epss": 0.1, "product": None})
        enriched.append(
            EnrichedCVE(
                cve=cve,
                cvss=float(meta.get("cvss", 0.0)),
                epss=float(meta.get("epss", 0.0)),
                product=meta.get("product"),
            )
        )
    return enriched


def enrich_blob(blob: str) -> List[Dict[str, float | str | None]]:
    cve_ids = extract_cves_from_text(blob)
    return [entry.as_dict() for entry in enrich_cves(cve_ids)]

