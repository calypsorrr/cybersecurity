from __future__ import annotations

from typing import Dict

from cybercheck.models.db import record_detection_run, upsert_detection_validation
from cybercheck.utils.capture import analyze_pcap_file


def register_validation(name: str, scenario: str, expected_signal: str) -> None:
    upsert_detection_validation(name, scenario, expected_signal)


def replay_pcap(path: str) -> Dict:
    return analyze_pcap_file(path)


def record_result(validation_id: int, result: str, notes: str | None = None) -> None:
    record_detection_run(validation_id, result, notes)
