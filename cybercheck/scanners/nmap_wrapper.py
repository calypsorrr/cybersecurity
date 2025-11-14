"""Helpers around invoking Nmap through :func:`run_tool`."""

from typing import List, Optional, Sequence

from cybercheck.config import NMAP_PROFILES
from cybercheck.scanners.runner import run_tool


def _resolve_profile(profile: str) -> Sequence[str]:
    """Return the CLI arguments for a configured profile.

    The UI surfaces the profiles from :mod:`cybercheck.config`; previously this
    module had its own hard-coded copy which could drift over time. By reading
    directly from the shared configuration we guarantee that UI selections map
    to the same behaviour the backend expects.
    """

    args = NMAP_PROFILES.get(profile)
    if args is None:
        raise ValueError(f"Unknown Nmap profile: {profile}")
    return list(args)


def nmap_scan(
    user: str,
    target: str,
    profile: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
):
    args: List[str] = []
    if profile:
        args.extend(_resolve_profile(profile))
    if extra_args:
        args.extend(str(arg) for arg in extra_args)
    args.append(target)  # target last
    return run_tool(user=user, tool="nmap", target=target, args=args)
