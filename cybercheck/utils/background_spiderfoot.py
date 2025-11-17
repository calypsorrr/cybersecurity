from __future__ import annotations

import os
import subprocess
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List

from cybercheck.models.db import log_run

try:
    from datetime import UTC
except ImportError:  # pragma: no cover - Python <3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc


class BackgroundSpiderfoot:
    """Run SpiderFoot in the background and stream output incrementally."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: Dict[str, Dict[str, Any]] = {}

    def start(
        self,
        *,
        user: str,
        target: str,
        target_type: str,
        modules: Iterable[str] | None = None,
    ) -> Dict[str, Any]:
        args: List[str] = ["-s", target, "-q"]
        if target_type:
            args.extend(["-t", target_type])

        modules_list = [m.strip() for m in modules or [] if m.strip()]
        if modules_list:
            args.extend(["-m", ",".join(modules_list)])

        cmd = ["sf"] + args
        started_at = datetime.now(UTC).isoformat()

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )

        run_id = str(uuid.uuid4())
        state: Dict[str, Any] = {
            "run_id": run_id,
            "proc": proc,
            "user": user,
            "target": target,
            "target_type": target_type,
            "modules": modules_list,
            "args": args,
            "started_at": started_at,
            "stdout_lines": [f"[launcher] running: {' '.join(cmd)}\n"],
            "stderr_lines": [],
        }

        with self._lock:
            self._runs[run_id] = state

        threading.Thread(
            target=self._stream_pipe,
            args=(proc.stdout, state, "stdout_lines"),
            daemon=True,
        ).start()
        threading.Thread(
            target=self._stream_pipe,
            args=(proc.stderr, state, "stderr_lines"),
            daemon=True,
        ).start()

        threading.Thread(target=self._monitor, args=(state,), daemon=True).start()

        return {"run_id": run_id, "started_at": started_at, "running": True}

    def status(self, run_id: str | None) -> Dict[str, Any] | None:
        if not run_id:
            return None

        with self._lock:
            state = self._runs.get(run_id)
            if not state:
                return None

            proc = state.get("proc")
            running = proc is not None and proc.poll() is None
            data = {
                "run_id": run_id,
                "running": running,
                "target": state.get("target"),
                "target_type": state.get("target_type"),
                "modules": state.get("modules", []),
                "started_at": state.get("started_at"),
                "finished_at": state.get("finished_at"),
                "returncode": state.get("returncode"),
                "stdout": "".join(state.get("stdout_lines", [])),
                "stderr": "".join(state.get("stderr_lines", [])),
            }
            return data

    def _monitor(self, state: Dict[str, Any]) -> None:
        proc: subprocess.Popen = state["proc"]
        proc.wait()
        finished_at = datetime.now(UTC).isoformat()

        with self._lock:
            state["returncode"] = proc.returncode
            state["finished_at"] = finished_at
            stdout_text = "".join(state.get("stdout_lines", []))
            stderr_text = "".join(state.get("stderr_lines", []))

        log_run(
            user=state.get("user", "operator"),
            tool="sf",
            target=state.get("target", "spiderfoot"),
            args=str(state.get("args", [])),
            started_at=state.get("started_at", finished_at),
            finished_at=finished_at,
            returncode=proc.returncode,
            stdout=stdout_text[:100000],
            stderr=stderr_text[:100000],
        )

    def _stream_pipe(self, pipe, state: Dict[str, Any], key: str) -> None:
        try:
            for line in iter(pipe.readline, ""):
                with self._lock:
                    state.setdefault(key, []).append(line)
        finally:  # pragma: no cover - safety guard
            try:
                pipe.close()
            except Exception:
                pass


background_spiderfoot = BackgroundSpiderfoot()
