from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

try:
    from datetime import UTC
except ImportError:  # pragma: no cover - py<3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

from cybercheck.models.db import log_run


def scapy_ping_scan(
    user: str,
    target: str,
    *,
    count: int = 4,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Perform a very small ICMP echo sweep using Scapy.

    Returns a dictionary mirroring the structure of `run_tool` responses
    and includes a ``report`` key with parsed details.
    """

    started_at = datetime.now(UTC).isoformat()
    stdout_lines: list[str] = []
    responses: list[Dict[str, Any]] = []
    stderr_text = ""
    returncode = 0
    report: Dict[str, Any] | None = None

    try:
        if count <= 0:
            raise ValueError("count must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        from scapy.all import ICMP, IP, conf, sr1  # type: ignore

        # Silence Scapy's verbose output; we format our own stdout below.
        conf.verb = 0

        received = 0
        for seq in range(1, count + 1):
            send_started = datetime.now(UTC)
            packet = IP(dst=target) / ICMP(seq=seq)
            answer = sr1(packet, timeout=timeout, verbose=False)
            if answer is not None:
                received += 1
                rtt_ms = (datetime.now(UTC) - send_started).total_seconds() * 1000
                ttl = getattr(answer, "ttl", None)
                src = getattr(answer, "src", target)
                responses.append(
                    {
                        "seq": seq,
                        "src": src,
                        "ttl": ttl,
                        "rtt_ms": rtt_ms,
                        "summary": answer.summary(),
                    }
                )
                ttl_display = ttl if ttl is not None else "?"
                stdout_lines.append(
                    f"reply from {src}: icmp_seq={seq} ttl={ttl_display} time={rtt_ms:.2f} ms"
                )
            else:
                responses.append(
                    {
                        "seq": seq,
                        "src": None,
                        "ttl": None,
                        "rtt_ms": None,
                        "summary": "timeout",
                    }
                )
                stdout_lines.append(f"request timeout for icmp_seq {seq}")

        loss_pct = ((count - received) / count) * 100 if count else 0.0
        status = "up" if received else "down"
        stdout_lines.append(f"--- {target} ping statistics ---")
        stdout_lines.append(
            f"{count} packets transmitted, {received} received, {loss_pct:.1f}% packet loss"
        )

        report = {
            "summary": {
                "target": target,
                "sent": count,
                "received": received,
                "loss_pct": round(loss_pct, 1),
                "status": status,
            },
            "responses": responses,
        }

        # Non-responsive hosts returncode mirrors the shell ping behavior (non-zero).
        returncode = 0 if received else 1

    except Exception as exc:  # pragma: no cover - runtime safeguard
        stderr_text = str(exc)
        returncode = -2

    finished_at = datetime.now(UTC).isoformat()
    stdout = "\n".join(stdout_lines)

    log_run(
        user=user,
        tool="scapy",
        target=target,
        args=str({"count": count, "timeout": timeout}),
        started_at=started_at,
        finished_at=finished_at,
        returncode=returncode,
        stdout=stdout[:100000],
        stderr=stderr_text[:100000],
    )

    result: Dict[str, Any] = {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr_text,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    if report is not None:
        result["report"] = report

    return result
