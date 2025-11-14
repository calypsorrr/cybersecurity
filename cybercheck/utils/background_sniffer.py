from __future__ import annotations

import subprocess
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, Sequence

from cybercheck.models.db import log_run
from cybercheck.scanners.ettercap_wrapper import build_ettercap_command

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    from datetime import timezone as _tz

    UTC = _tz.utc


class BackgroundSniffer:
    """Manage a single long-running Ettercap sniff session."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Dict[str, Any] | None = None

    def start(
        self,
        *,
        user: str,
        interface: str,
        quiet: bool = True,
        text_mode: bool = True,
        target_a: str | None = None,
        target_b: str | None = None,
        plugin: str | None = None,
        filter_script: str | None = None,
        log_file: str | None = None,
        pcap_file: str | None = None,
        extra_args: Sequence[str] | None = None,
    ) -> Dict[str, Any]:
        with self._lock:
            if self._state and self._state.get("proc") and self._state["proc"].poll() is None:
                raise RuntimeError("Sniffing already in progress. Stop it before launching another session.")

        args, summary, target_display = build_ettercap_command(
            user=user,
            interface=interface,
            operation="sniff",
            quiet=quiet,
            text_mode=text_mode,
            target_a=target_a,
            target_b=target_b,
            plugin=plugin,
            filter_script=filter_script,
            log_file=log_file,
            pcap_file=pcap_file,
            extra_args=extra_args,
        )

        cmd = ["ettercap"] + args
        started_at = datetime.now(UTC).isoformat()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Ettercap binary is not available on this system.") from exc

        run_id = str(uuid.uuid4())
        state = {
            "run_id": run_id,
            "proc": proc,
            "user": user,
            "target": target_display,
            "args": args,
            "summary": summary,
            "started_at": started_at,
        }

        with self._lock:
            self._state = state

        watcher = threading.Thread(target=self._monitor_process, args=(state,), daemon=True)
        watcher.start()

        return {
            "running": True,
            "run_id": run_id,
            "summary": summary,
            "started_at": started_at,
            "message": "Sniffing started in the background.",
        }

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            state = self._state
            if not state or state["proc"].poll() is not None:
                return {
                    "running": False,
                    "summary": state.get("summary") if state else None,
                    "message": "No sniffing session is currently running.",
                }
            proc = state["proc"]

        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return {"running": False, "message": "Sniffing stopped."}

    def status(self) -> Dict[str, Any]:
        with self._lock:
            state = self._state
            if not state:
                return {"running": False}
            running = state["proc"].poll() is None
            data = {
                "running": running,
                "run_id": state.get("run_id"),
                "summary": state.get("summary"),
                "started_at": state.get("started_at"),
                "finished_at": state.get("finished_at"),
                "returncode": state.get("returncode"),
            }
            if not running:
                data["stdout"] = state.get("stdout", "")
                data["stderr"] = state.get("stderr", "")
            return data

    def _monitor_process(self, state: Dict[str, Any]) -> None:
        proc = state["proc"]
        try:
            stdout, stderr = proc.communicate()
        except Exception as exc:  # pragma: no cover - safety guard
            stdout = ""
            stderr = str(exc)
        finished_at = datetime.now(UTC).isoformat()

        with self._lock:
            state["returncode"] = proc.returncode
            state["stdout"] = stdout
            state["stderr"] = stderr
            state["finished_at"] = finished_at

        log_run(
            user=state.get("user", "operator"),
            tool="ettercap",
            target=state.get("target", "ettercap"),
            args=str(state.get("args", [])),
            started_at=state.get("started_at", finished_at),
            finished_at=finished_at,
            returncode=proc.returncode,
            stdout=stdout[:100000],
            stderr=stderr[:100000],
        )


background_sniffer = BackgroundSniffer()
