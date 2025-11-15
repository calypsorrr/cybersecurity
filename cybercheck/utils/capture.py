"""Wireshark-style capture helpers for the Flask UI."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # pragma: no cover - Py<3.11 fallback
    from datetime import UTC
except ImportError:  # pragma: no cover - Py<3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

from cybercheck.models.db import log_run
from cybercheck.utils.wireshark_filters import (
    HIGH_VALUE_PORTS,
    SENSITIVE_PROTOCOL_FILTERS,
    build_filter_suggestion,
)


def _format_counter(counter: Counter, limit: int = 5) -> List[Dict[str, Any]]:
    return [
        {"label": label, "count": int(count)}
        for label, count in counter.most_common(limit)
    ]


def _pair_counter(counter: Counter, limit: int = 5) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for (src, dst), count in counter.most_common(limit):
        items.append({"src": src or "?", "dst": dst or "?", "count": int(count)})
    return items


def _summarize_packets(
    packets: Iterable[Any],
    *,
    include_hex: bool,
    hexdump_fn,
    default_timestamp: float,
    sample_limit: Optional[int] = 60,
) -> Dict[str, Any]:
    """Return aggregate stats and sample rows from a packet iterable."""

    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.l2 import ARP, Ether  # type: ignore

    # IPv6 is in inet6 for many Scapy versions; fall back gracefully if unavailable
    try:  # pragma: no cover - optional IPv6 layer
        from scapy.layers.inet6 import IPv6  # type: ignore
    except Exception:  # pragma: no cover - IPv6 layer unavailable
        IPv6 = None  # type: ignore

    try:  # pragma: no cover - optional dependency
        from scapy.layers.dns import DNS  # type: ignore
    except Exception:  # pragma: no cover - DNS layer unavailable
        DNS = None  # type: ignore

    proto_counter: Counter[str] = Counter()
    talkers: Counter[str] = Counter()
    targets: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    pairs: Counter[Tuple[Optional[str], Optional[str]]] = Counter()

    samples: List[Dict[str, Any]] = []
    all_samples: List[Dict[str, Any]] = []
    stdout_lines: List[str] = []

    total_bytes = 0
    captured = 0
    earliest_ts: Optional[float] = None
    latest_ts: Optional[float] = None

    def _proto_label(pkt) -> str:
        if DNS and pkt.haslayer(DNS):  # type: ignore[attr-defined]
            return "DNS"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(ARP):
            return "ARP"
        if IPv6 and pkt.haslayer(IPv6):
            return "IPv6"
        if pkt.haslayer(IP):
            return "IP"
        if pkt.haslayer(Ether):
            return "Ethernet"
        return getattr(pkt.lastlayer(), "name", pkt.__class__.__name__)

    for packet in packets:
        captured += 1
        length = int(len(packet))
        total_bytes += length

        ts_value = float(getattr(packet, "time", default_timestamp))
        if earliest_ts is None or ts_value < earliest_ts:
            earliest_ts = ts_value
        if latest_ts is None or ts_value > latest_ts:
            latest_ts = ts_value

        timestamp = datetime.fromtimestamp(ts_value, UTC)

        src = dst = None
        src_port = dst_port = None
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 and packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst

        if packet.haslayer(TCP):
            try:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
            except Exception:
                src_port = dst_port = None
        elif packet.haslayer(UDP):
            try:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            except Exception:
                src_port = dst_port = None

        proto = _proto_label(packet)
        proto_counter[proto] += 1

        if src:
            talkers[src] += 1
        if dst:
            targets[dst] += 1
        if src or dst:
            pairs[(src, dst)] += 1

        if isinstance(dst_port, int):
            ports[f"{proto}:{dst_port}"] += 1

        summary = packet.summary()
        stdout_lines.append(
            f"{timestamp.isoformat()} {src or '?'} -> {dst or '?'} {summary}"
        )

        sample_entry = {
            "timestamp": timestamp.isoformat(timespec="seconds"),
            "src": src or "?",
            "dst": dst or "?",
            "proto": proto,
            "length": length,
            "info": summary,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        if include_hex:
            sample_entry["hex"] = hexdump_fn(packet, dump=True)

        all_samples.append(sample_entry)

        if sample_limit is None or len(samples) < sample_limit:
            samples.append(sample_entry)

    return {
        "captured": captured,
        "total_bytes": total_bytes,
        "protocols": _format_counter(proto_counter, limit=6),
        "talkers": _format_counter(talkers, limit=6),
        "targets": _format_counter(targets, limit=6),
        "ports": _format_counter(ports, limit=6),
        "pairs": _pair_counter(pairs, limit=6),
        "samples": samples,
        "all_samples": all_samples,
        "stdout_lines": stdout_lines,
        "earliest_ts": earliest_ts,
        "latest_ts": latest_ts,
    }


def capture_packets(
    *,
    user: str,
    interface: Optional[str],
    bpf_filter: Optional[str],
    packet_limit: int = 200,
    duration: float = 8.0,
    include_hex: bool = False,
) -> Dict[str, Any]:
    """Sniff a short burst of packets and summarize them for the UI."""

    started = datetime.now(UTC)
    started_at = started.isoformat()

    packet_limit = max(1, min(packet_limit, 500))
    duration = max(1.0, min(duration, 60.0))

    stdout_lines: List[str] = []
    stderr_text = ""
    returncode = 0
    report: Optional[Dict[str, Any]] = None

    log_args = {
        "interface": interface,
        "bpf": bpf_filter,
        "limit": packet_limit,
        "duration": duration,
        "include_hex": include_hex,
    }

    try:
        from scapy.all import hexdump, sniff  # type: ignore

        packets = sniff(
            iface=interface or None,
            filter=bpf_filter or None,
            count=packet_limit,
            timeout=duration,
            store=True,
        )

        stats = _summarize_packets(
            packets,
            include_hex=include_hex,
            hexdump_fn=hexdump,
            default_timestamp=started.timestamp(),
        )
        stdout_lines = stats.pop("stdout_lines")

        duration_elapsed = max((datetime.now(UTC) - started).total_seconds(), 0.001)
        bandwidth_bps = int((stats["total_bytes"] * 8) / duration_elapsed)

        report = {
            "summary": {
                "captured": stats["captured"],
                "bytes": stats["total_bytes"],
                "bandwidth_bps": bandwidth_bps,
                "duration": duration_elapsed,
                "interface": interface or "default",
                "filter": bpf_filter or "(none)",
                "mode": "capture",
                "source_label": interface or "default",
            },
            "protocols": stats["protocols"],
            "talkers": stats["talkers"],
            "targets": stats["targets"],
            "ports": stats["ports"],
            "pairs": stats["pairs"],
            "samples": stats["samples"],
            "all_samples": stats["all_samples"],
        }
        report["filter_advice"] = build_filter_suggestion(report)

        if not stats["captured"]:
            returncode = 1

    except Exception as exc:  # pragma: no cover - runtime safeguard
        stderr_text = str(exc)
        returncode = -1

    finished_at = datetime.now(UTC).isoformat()
    stdout = "\n".join(stdout_lines)

    log_run(
        user=user,
        tool="pcap",
        target=interface or "default",
        args=str(log_args),
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


def analyze_pcap_file(
    *,
    user: str,
    file_path: str | Path,
    include_hex: bool = False,
    original_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Read a PCAP file from disk and summarize it for the UI."""

    started = datetime.now(UTC)
    started_at = started.isoformat()
    file_path = Path(file_path)

    stdout_lines: List[str] = []
    stderr_text = ""
    returncode = 0
    report: Optional[Dict[str, Any]] = None

    log_args = {
        "file": str(file_path),
        "include_hex": include_hex,
    }

    try:
        from scapy.all import hexdump  # type: ignore
        from scapy.utils import PcapReader  # type: ignore

        reader = PcapReader(str(file_path))
        try:
            stats = _summarize_packets(
                reader,
                include_hex=include_hex,
                hexdump_fn=hexdump,
                default_timestamp=started.timestamp(),
                sample_limit=120,
            )
        finally:
            reader.close()

        stdout_lines = stats.pop("stdout_lines")

        duration_window = 0.0
        earliest = stats.get("earliest_ts")
        latest = stats.get("latest_ts")
        if earliest is not None and latest is not None and latest >= earliest:
            duration_window = float(latest - earliest)

        bandwidth_bps = int(
            (stats["total_bytes"] * 8) / duration_window
        ) if duration_window > 0 else 0

        label = original_name or file_path.name or "uploaded.pcap"

        report = {
            "summary": {
                "captured": stats["captured"],
                "bytes": stats["total_bytes"],
                "bandwidth_bps": bandwidth_bps,
                "duration": duration_window,
                "interface": label,
                "filter": "pcap upload",
                "mode": "pcap",
                "source_label": label,
            },
            "protocols": stats["protocols"],
            "talkers": stats["talkers"],
            "targets": stats["targets"],
            "ports": stats["ports"],
            "pairs": stats["pairs"],
            "samples": stats["samples"],
            "all_samples": stats["all_samples"],
        }
        report["filter_advice"] = build_filter_suggestion(report)

        if not stats["captured"]:
            returncode = 1

    except Exception as exc:  # pragma: no cover - runtime safeguard
        stderr_text = str(exc)
        returncode = -1

    finished_at = datetime.now(UTC).isoformat()
    stdout = "\n".join(stdout_lines)

    log_run(
        user=user,
        tool="pcap-file",
        target=str(file_path),
        args=str(log_args),
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


def extract_interesting_packets(report: Dict[str, Any] | None) -> List[Dict[str, Any]]:
    """Return packets that look worth triaging based on heuristics."""

    if not report:
        return []

    samples = report.get("all_samples") or []
    if not samples:
        return []

    interesting_hosts = set()
    for collection in (report.get("talkers") or [], report.get("targets") or []):
        for entry in collection[:2]:
            label = entry.get("label")
            if label:
                interesting_hosts.add(label)

    sensitive_protocols = {proto.upper() for proto in SENSITIVE_PROTOCOL_FILTERS.keys()}
    high_value_ports = set(HIGH_VALUE_PORTS.keys())

    flagged: List[Dict[str, Any]] = []
    for packet in samples:
        highlights: List[str] = []
        proto = (packet.get("proto") or "").upper()
        src = packet.get("src")
        dst = packet.get("dst")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")

        if proto in sensitive_protocols:
            _, rationale = SENSITIVE_PROTOCOL_FILTERS[proto]
            highlights.append(rationale)

        if src in interesting_hosts:
            highlights.append(f"{src} ranked among the busiest hosts.")
        if dst in interesting_hosts and dst != src:
            highlights.append(f"{dst} ranked among the busiest hosts.")

        for port in (src_port, dst_port):
            if isinstance(port, int) and port in high_value_ports:
                highlights.append(f"Traffic touches {HIGH_VALUE_PORTS[port]} (port {port}).")

        if highlights:
            entry = dict(packet)
            entry["highlights"] = highlights
            flagged.append(entry)

    return flagged
