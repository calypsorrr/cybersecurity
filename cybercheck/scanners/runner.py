import subprocess
from typing import List, Optional, Dict, Any
from datetime import datetime
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc

from cybercheck.config import DEFAULT_TIMEOUT, ALLOWED_TOOLS
from cybercheck.models.db import log_run


def run_tool(user: str, tool: str, target: str, args: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowed: {tool}")

    args = list(map(str, args))
    cmd = [tool] + args

    started = datetime.now(UTC).isoformat()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout or DEFAULT_TIMEOUT,
            shell=False,
        )
        finished = datetime.now(UTC).isoformat()
        log_run(
            user=user,
            tool=tool,
            target=target,
            args=str(args),
            started_at=started,
            finished_at=finished,
            returncode=proc.returncode,
            stdout=proc.stdout[:100000],
            stderr=proc.stderr[:100000],
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "started_at": started,
            "finished_at": finished,
        }
    except subprocess.TimeoutExpired as e:
        finished = datetime.now(UTC).isoformat()
        log_run(
            user=user,
            tool=tool,
            target=target,
            args=str(args),
            started_at=started,
            finished_at=finished,
            returncode=-1,
            stdout="",
            stderr=f"timeout: {str(e)}",
        )
        return {"error": "timeout", "stderr": str(e), "started_at": started, "finished_at": finished}
    except Exception as e:
        finished = datetime.now(UTC).isoformat()
        log_run(
            user=user,
            tool=tool,
            target=target,
            args=str(args),
            started_at=started,
            finished_at=finished,
            returncode=-2,
            stdout="",
            stderr=str(e),
        )
        return {"error": "exception", "stderr": str(e), "started_at": started, "finished_at": finished}
