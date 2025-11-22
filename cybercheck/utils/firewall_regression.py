from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Tuple

from cybercheck.models.db import (
    fetch_firewall_expectations,
    update_firewall_observation,
)
from cybercheck.scanners import nmap_scan


def run_firewall_matrix(target: str, expectations: Iterable[Tuple[int, str]]) -> List[dict]:
    """
    expectations: iterable of (port, expected_action)
    expected_action: "allow" or "deny"
    """
    results = []
    for port, expected_action in expectations:
        ports = str(port)
        scan = nmap_scan(target, extra_args=["-p", ports, "-sS", "-Pn"])
        observed = "allow" if "open" in scan.get("stdout", "") else "deny"
        results.append({"port": port, "expected": expected_action, "observed": observed})
    return results


def persist_firewall_findings(findings: Iterable[Tuple[int, str]]):
    for expectation_id, observed_action in findings:
        update_firewall_observation(expectation_id, observed_action)


def collect_expectations():
    return fetch_firewall_expectations()
