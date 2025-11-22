from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Tuple

from cybercheck.models.db import (
    fetch_firewall_expectations,
    update_firewall_observation,
)
from cybercheck.scanners import nmap_scan


def _normalize_expectations(
    expectations: Iterable[Tuple[int, str]] | Iterable[dict],
) -> List[Tuple[int, str]]:
    normalized: List[Tuple[int, str]] = []
    for item in expectations:
        if isinstance(item, dict):
            port = item.get("port")
            expected = item.get("expect") or item.get("expected")
        else:
            try:
                port, expected = item
            except Exception:
                continue
        if port is None or expected is None:
            continue
        normalized.append((int(port), str(expected).lower()))
    return normalized


def run_firewall_matrix(
    user: str,
    target: str,
    expectations: Iterable[Tuple[int, str]] | Iterable[dict],
) -> List[dict]:
    """Run expectations against a target using Nmap scans."""

    results = []
    for port, expected_action in _normalize_expectations(expectations):
        ports = str(port)
        scan = nmap_scan(user=user, target=target, extra_args=["-p", ports, "-sS", "-Pn"])
        observed = "allow" if "open" in scan.get("stdout", "") else "deny"
        results.append(
            {
                "port": port,
                "expected": expected_action,
                "observed": observed,
                "stdout": scan.get("stdout", ""),
            }
        )
    return results


def persist_firewall_findings(findings: Iterable[Tuple[int, str]]):
    for expectation_id, observed_action in findings:
        update_firewall_observation(expectation_id, observed_action)


def collect_expectations():
    return fetch_firewall_expectations()


def run_firewall_pentest(user: str, target: str) -> dict:
    default_checks = [
        {"service": "SSH", "port": 22, "expect": "deny"},
        {"service": "RDP", "port": 3389, "expect": "deny"},
        {"service": "WinRM", "port": 5985, "expect": "deny"},
        {"service": "SQL Server", "port": 1433, "expect": "deny"},
        {"service": "Postgres", "port": 5432, "expect": "deny"},
        {"service": "HTTP", "port": 80, "expect": "allow"},
        {"service": "HTTPS", "port": 443, "expect": "allow"},
    ]

    matrix_results = run_firewall_matrix(user, target, default_checks)

    findings = []
    for check, result in zip(default_checks, matrix_results):
        recommendation = None
        if result["observed"] != result["expected"]:
            if result["expected"] == "deny":
                recommendation = f"Restrict or close {check['service']} (port {check['port']}) to reduce exposure."
            else:
                recommendation = f"Allow-list traffic to {check['service']} (port {check['port']}) or adjust rules to avoid false negatives."
        else:
            recommendation = f"{check['service']} (port {check['port']}) matches the expected policy."

        findings.append(
            {
                "service": check["service"],
                "port": check["port"],
                "expected": result["expected"],
                "observed": result["observed"],
                "recommendation": recommendation,
            }
        )

    exposed = [f for f in findings if f["expected"] == "deny" and f["observed"] == "allow"]
    blocked = [f for f in findings if f["expected"] == "allow" and f["observed"] == "deny"]

    summary = {
        "target": target,
        "exposed_services": len(exposed),
        "blocked_legitimate": len(blocked),
        "status": "attention" if exposed or blocked else "pass",
    }

    recommendations = [f["recommendation"] for f in findings if f["recommendation"]]

    return {
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
    }
