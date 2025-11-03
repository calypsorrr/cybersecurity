from typing import Iterable, List, Optional, Union
from cybercheck.scanners.runner import run_tool


def _normalize_args(extra_args: Optional[Union[str, Iterable[str]]]) -> List[str]:
    if extra_args is None:
        return ["-nointeractive"]
    if isinstance(extra_args, str):
        return [extra_args]
    return list(extra_args)


def nikto_scan(user: str, target_url: str, extra_args: Optional[Union[str, Iterable[str]]] = None):
    args = ["-host", target_url] + _normalize_args(extra_args)
    return run_tool(user=user, tool="nikto", target=target_url, args=args)
