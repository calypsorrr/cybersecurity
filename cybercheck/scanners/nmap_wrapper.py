# Minimal wrapper for nmap usage: builds args from a profile + extra args and runs via the common runner.
from typing import List, Optional
from cybercheck.scanners.runner import run_tool

# Keep in sync with config.NMAP_PROFILES if you want central control
_PROFILE_MAP = {
    "quick": ["-F", "-sV", "-Pn"],
    "top-ports": ["--top-ports", "100", "-sV", "-Pn"],
    "full-tcp": ["-p-", "-sV", "-Pn"],
    "udp": ["-sU", "-Pn"],
    "vuln-scan": ["-sV", "-Pn", "--script", "vuln"],
}

def nmap_scan(user: str, target: str, profile: Optional[str] = None, extra_args: Optional[List[str]] = None):
    args: List[str] = []
    if profile and profile in _PROFILE_MAP:
        args.extend(_PROFILE_MAP[profile])
    if extra_args:
        args.extend(extra_args)
    args.append(target)  # target last
    return run_tool(user=user, tool="nmap", target=target, args=args)
