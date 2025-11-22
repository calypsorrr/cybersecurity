from __future__ import annotations

import importlib
import json
import shlex
from typing import Any, Dict, Optional

APSCHEDULER_AVAILABLE = all(
    importlib.util.find_spec(path) is not None
    for path in ["apscheduler.schedulers.background", "apscheduler.triggers.cron"]
)

if APSCHEDULER_AVAILABLE:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
else:
    class BackgroundScheduler:  # type: ignore[misc]
        """Minimal no-op scheduler fallback when APScheduler is unavailable."""

        def __init__(self) -> None:
            self._jobs = []

        def start(self) -> None:
            return None

        def shutdown(self, wait: bool = False) -> None:
            self._jobs.clear()

        def remove_all_jobs(self) -> None:
            self._jobs.clear()

        def add_job(self, *_, **__):  # pragma: no cover - noop
            return None

    class CronTrigger:  # type: ignore[misc]
        @classmethod
        def from_crontab(cls, expression: str):  # pragma: no cover - noop
            raise RuntimeError(
                "APScheduler is not installed; cannot parse cron expressions."
            )

from cybercheck.models.db import fetch_schedules, record_schedule_run
from cybercheck.scanners.runner import run_tool


class ScanScheduler:
    def __init__(self) -> None:
        self.scheduler = BackgroundScheduler()
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        self.scheduler.start()
        self.started = True

    def shutdown(self) -> None:
        if not self.started:
            return
        self.scheduler.shutdown(wait=False)
        self.started = False

    def load_jobs(self) -> None:
        # Clear existing jobs before reloading
        self.scheduler.remove_all_jobs()
        if not APSCHEDULER_AVAILABLE:
            return

        for job in fetch_schedules(enabled_only=True):
            cron = (job.get("cron") or "").strip()
            if not cron:
                # Skip jobs without a cron expression instead of raising at add_job
                continue
            try:
                trigger = CronTrigger.from_crontab(cron)
            except Exception:
                # Ignore invalid cron syntax to keep the scheduler running
                continue
            self.scheduler.add_job(
                self._run_job,
                trigger,
                id=f"schedule-{job['id']}",
                kwargs={"job": dict(job)},
                replace_existing=True,
            )

    def _run_job(self, job: Dict[str, Any]) -> None:
        args = job.get("args") or ""
        parsed_args = json.loads(args) if args and args.strip().startswith("[") else shlex.split(args) if args else []
        run_tool(job.get("tool"), parsed_args, timeout=300, user="scheduler", target=job.get("target", ""))
        record_schedule_run(job["id"])


scan_scheduler = ScanScheduler()
