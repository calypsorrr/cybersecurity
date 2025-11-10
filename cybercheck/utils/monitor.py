"""Background network monitoring utilities for the dashboard.

This module keeps a lightweight packet sniffer running in the background and
surfaces aggregated telemetry that the Flask views and API endpoints can
consume.  The intent is to provide situational awareness – protocol mix,
top talkers, throughput – and raise simple heuristics for suspicious bursts
such as volumetric floods that might come from tooling like Scapy.

The monitor is written defensively so that environments without raw socket
permissions (or where Scapy is unavailable) degrade gracefully while still
returning useful state to the UI.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
import threading
import time
from typing import Deque, Dict, List, Optional

try:  # pragma: no cover - fallback for Python <3.11
    from datetime import UTC
except ImportError:  # pragma: no cover - fallback
    from datetime import timezone as _tz

    UTC = _tz.utc


def _now() -> datetime:
    return datetime.now(UTC)


def _total(counter: Counter) -> int:
    return int(sum(counter.values()))


def _format_counter(counter: Counter, limit: int = 5) -> List[Dict[str, object]]:
    return [
        {"key": key, "count": int(count)}
        for key, count in counter.most_common(limit)
    ]


@dataclass
class PacketRecord:
    ts: float
    src: str
    dst: str


class NetworkMonitor:
    """Maintain rolling packet statistics for the dashboard."""

    def __init__(
        self,
        *,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        window_seconds: int = 10,
        alert_threshold: int = 120,
        dst_threshold: int = 160,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.window_seconds = window_seconds
        self.alert_threshold = alert_threshold
        self.dst_threshold = dst_threshold

        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._error: Optional[str] = None
        self._started_at: Optional[datetime] = None

        self._packet_total = 0
        self._byte_total = 0
        self._protocols: Counter[str] = Counter()
        self._src_counter: Counter[str] = Counter()
        self._dst_counter: Counter[str] = Counter()

        self._recent_packets: Deque[Dict[str, object]] = deque(maxlen=40)
        self._window: Deque[PacketRecord] = deque()
        self._window_src: Counter[str] = Counter()
        self._window_dst: Counter[str] = Counter()
        self._alert_log: Deque[Dict[str, object]] = deque(maxlen=50)

    # ------------------------------------------------------------------
    # Thread lifecycle
    def ensure_running(self) -> None:
        if self._running or self._error:
            return

        self._running = True
        self._started_at = _now()
        self._thread = threading.Thread(target=self._worker, name="network-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    # ------------------------------------------------------------------
    # Core sniffing loop
    def _worker(self) -> None:
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as exc:  # pragma: no cover - import failure guard
            with self._lock:
                self._error = f"Scapy unavailable for live monitoring: {exc}"
                self._running = False
            return

        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    store=False,
                    prn=self._handle_packet,
                    timeout=1,
                )
            except Exception as exc:  # pragma: no cover - runtime safeguard
                with self._lock:
                    self._error = f"Sniffer error: {exc}"
                    self._running = False
                break

    # ------------------------------------------------------------------
    # Packet processing
    def _handle_packet(self, packet) -> None:  # type: ignore[override]
        now = time.time()

        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
            from scapy.layers.l2 import ARP, Ether  # type: ignore
        except Exception:  # pragma: no cover - should not happen
            return

        proto = "OTHER"
        src = "?"
        dst = "?"

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        elif packet.haslayer(ARP):
            proto = "ARP"

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(ARP):
            src = getattr(packet[ARP], "psrc", src)
            dst = getattr(packet[ARP], "pdst", dst)
        elif packet.haslayer(Ether):
            src = getattr(packet[Ether], "src", src)
            dst = getattr(packet[Ether], "dst", dst)

        size = int(len(packet))

        with self._lock:
            self._packet_total += 1
            self._byte_total += size
            self._protocols[proto] += 1
            self._src_counter[src] += 1
            self._dst_counter[dst] += 1

            self._recent_packets.appendleft(
                {
                    "time": datetime.fromtimestamp(now, tz=UTC).isoformat(),
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "size": size,
                    "summary": packet.summary(),
                }
            )

            self._window.append(PacketRecord(ts=now, src=src, dst=dst))
            self._window_src[src] += 1
            self._window_dst[dst] += 1

            self._prune_window(now)
            self._evaluate_alerts(now)

    def _prune_window(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._window and self._window[0].ts < cutoff:
            record = self._window.popleft()
            self._window_src[record.src] -= 1
            if self._window_src[record.src] <= 0:
                del self._window_src[record.src]
            self._window_dst[record.dst] -= 1
            if self._window_dst[record.dst] <= 0:
                del self._window_dst[record.dst]

    def _evaluate_alerts(self, now: float) -> None:
        window_packets = _total(self._window_src)

        def _log(message: str, severity: str = "warning") -> None:
            recent = self._alert_log[0]["message"] if self._alert_log else None
            if recent == message:
                return
            self._alert_log.appendleft(
                {
                    "time": datetime.fromtimestamp(now, tz=UTC).isoformat(),
                    "message": message,
                    "severity": severity,
                }
            )

        for src, count in list(self._window_src.items()):
            if count >= self.alert_threshold:
                _log(
                    f"High inbound volume from {src}: {count} packets in the last {self.window_seconds}s",
                    severity="danger",
                )

        for dst, count in list(self._window_dst.items()):
            if count >= self.dst_threshold:
                _log(
                    f"Concentrated flow towards {dst}: {count} packets observed in {self.window_seconds}s",
                    severity="danger",
                )

        if window_packets >= max(self.alert_threshold, self.dst_threshold) * 1.5:
            _log(
                f"Sustained burst detected: {window_packets} packets captured in {self.window_seconds}s window",
                severity="warning",
            )

    # ------------------------------------------------------------------
    # Data exposure
    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            uptime: Optional[float] = None
            if self._started_at:
                uptime = max((_now() - self._started_at).total_seconds(), 0)

            protocols = dict(self._protocols)
            totals = {
                "packets": self._packet_total,
                "bytes": self._byte_total,
            }

            window_packets = _total(self._window_src)
            rate = (window_packets / self.window_seconds) if self.window_seconds else 0.0

            return {
                "running": self._running,
                "interface": self.interface,
                "filter": self.bpf_filter,
                "error": self._error,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "uptime": uptime,
                "totals": totals,
                "protocols": protocols,
                "top_sources": _format_counter(self._src_counter),
                "top_destinations": _format_counter(self._dst_counter),
                "recent_packets": list(self._recent_packets)[:10],
                "alert_log": list(self._alert_log)[:10],
                "window": {
                    "seconds": self.window_seconds,
                    "packets": window_packets,
                    "rate": rate,
                },
            }


# Singleton used by the Flask application
network_monitor = NetworkMonitor()

