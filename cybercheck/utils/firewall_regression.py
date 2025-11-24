from __future__ import annotations

import re
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

    deep_checks = _run_deeper_firewall_probes(user, target)
    open_services = _summarize_open_services(deep_checks)

    return {
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
        "deep_checks": deep_checks,
        "open_services": open_services,
    }


def _run_deeper_firewall_probes(user: str, target: str) -> List[dict]:
    """Perform additional discovery beyond the allow/deny matrix.

    The baseline pentest only checks a handful of curated ports. These extra probes
    map more of the attack surface with service/version detection and a light
    vulnerability sweep so analysts can quickly pivot into targeted follow-ups.
    """

    profiles = [
        {
            "name": "Top 100 TCP (service discovery)",
            "profile": "top-ports",
            "description": "Discovers commonly exposed TCP services with version detection",
            "extra_args": ["--open", "--reason"],
        },
        {
            "name": "HTTP surface mapping",
            "profile": "http-enum",
            "description": "Enumerates web endpoints on common HTTP/S ports",
            "extra_args": ["--open", "--reason"],
        },
        {
            "name": "Lightweight vuln scan",
            "profile": "vuln-scan",
            "description": "Runs Nmap's built-in vuln scripts against discovered services",
            "extra_args": ["--open", "--reason"],
        },
    ]

    results: List[dict] = []
    for probe in profiles:
        scan = nmap_scan(
            user=user,
            target=target,
            profile=probe["profile"],
            extra_args=probe.get("extra_args"),
        )
        results.append(
            {
                "name": probe["name"],
                "description": probe["description"],
                "profile": probe["profile"],
                "stdout": scan.get("stdout", ""),
                "stderr": scan.get("stderr", ""),
                "returncode": scan.get("returncode"),
            }
        )
    return results


_PORT_LINE = re.compile(
    r"^(?P<port>\d{1,5})/(tcp|udp)\s+open(?:\S*)\s+(?P<service>[\w\-\.]+)?(?P<details>.*)$",
    re.IGNORECASE,
)


def _summarize_open_services(deep_checks: Iterable[dict]) -> List[dict]:
    """Extract open service details from deep probe output for quick triage."""

    findings: List[dict] = []
    for check in deep_checks:
        stdout = check.get("stdout") or ""
        for line in stdout.splitlines():
            match = _PORT_LINE.match(line.strip())
            if not match:
                continue
            findings.append(
                {
                    "port": int(match.group("port")),
                    "service": (match.group("service") or "").strip() or None,
                    "details": (match.group("details") or "").strip() or None,
                    "source": check.get("name"),
                }
            )
    # Keep results ordered by port to make the UI stable and legible
    findings.sort(key=lambda f: f.get("port", 0))
    return findings
