from __future__ import annotations

import json
import shlex
from typing import Any, Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

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
        for job in fetch_schedules(enabled_only=True):
            trigger = CronTrigger.from_crontab(job["cron"]) if job["cron"] else None
            self.scheduler.add_job(
                self._run_job,
                trigger or "interval",
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
