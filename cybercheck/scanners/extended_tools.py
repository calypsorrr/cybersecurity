from __future__ import annotations

"""Wrappers for app/API DAST, supply chain, and forensics tooling."""

from typing import Any, Dict, Iterable, List

from cybercheck.scanners.runner import run_tool


def zap_scan(
    *,
    user: str,
    target: str,
    mode: str = "baseline",
    api_def: str | None = None,
    policy: str | None = None,
    ajax_spider: bool = False,
    extra_args: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Run an OWASP ZAP automation profile.

    mode: baseline | api | full
    api_def: OpenAPI/Swagger file or URL for API mode
    """

    if mode not in {"baseline", "api", "full"}:
        raise ValueError("Invalid ZAP mode; choose baseline, api, or full")

    tool = {
        "baseline": "zap-baseline.py",
        "api": "zap-api-scan.py",
        "full": "zap-full-scan.py",
    }[mode]

    args: List[str] = ["-t", target, "-J", "-", "-r", "-", "-z", "-addonupdate"]
    if api_def:
        args.extend(["-f", api_def])
    if policy:
        args.extend(["-P", policy])
    if ajax_spider:
        args.extend(["-j"])
    if extra_args:
        args.extend(list(extra_args))

    return run_tool(user=user, tool=tool, target=target, args=args)


def gitleaks_scan(*, user: str, target: str) -> Dict[str, Any]:
    args = ["detect", "-s", target, "--no-banner", "--report-format", "json"]
    return run_tool(user=user, tool="gitleaks", target=target, args=args)


def trufflehog_scan(*, user: str, target: str) -> Dict[str, Any]:
    args = ["filesystem", target, "--json", "--fail"]
    return run_tool(user=user, tool="trufflehog", target=target, args=args)


def trivy_scan(*, user: str, target: str, list_vulns: bool = True) -> Dict[str, Any]:
    args = ["image", target, "--format", "table"]
    if list_vulns:
        args.extend(["--ignore-unfixed"])
    return run_tool(user=user, tool="trivy", target=target, args=args)


def grype_scan(*, user: str, target: str) -> Dict[str, Any]:
    args = [target, "--output", "table"]
    return run_tool(user=user, tool="grype", target=target, args=args)


def checkov_scan(*, user: str, target: str) -> Dict[str, Any]:
    args = ["-d", target, "--quiet", "--compact"]
    return run_tool(user=user, tool="checkov", target=target, args=args)


def volatility_inspect(*, user: str, target: str, plugin: str = "pslist") -> Dict[str, Any]:
    args = ["-f", target, plugin]
    return run_tool(user=user, tool="volatility3", target=target, args=args)


def spiderfoot_scan(
    *,
    user: str,
    target: str,
    modules: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Run SpiderFoot CLI for OSINT-style recon."""

    args: List[str] = ["-s", target, "-q"]
    if modules:
        args.extend(["-m", ",".join(modules)])

    return run_tool(user=user, tool="sf", target=target, args=args)

