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
    from scapy.packet import NoPayload, Packet  # type: ignore

    # IPv6 is in inet6 for many Scapy versions; fall back gracefully if unavailable
    try:  # pragma: no cover - optional IPv6 layer
        from scapy.layers.inet6 import IPv6  # type: ignore
    except Exception:  # pragma: no cover - IPv6 layer unavailable
        IPv6 = None  # type: ignore

    try:  # pragma: no cover - optional dependency
        from scapy.layers.dns import DNS  # type: ignore
    except Exception:  # pragma: no cover - DNS layer unavailable
        DNS = None  # type: ignore

    # Import HTTP dissectors if available so Scapy registers them for parsing
    try:  # pragma: no cover - optional dependency
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse  # type: ignore
    except Exception:  # pragma: no cover - HTTP layer unavailable
        HTTP = HTTPRequest = HTTPResponse = None  # type: ignore

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
        if HTTPRequest and pkt.haslayer(HTTPRequest):  # type: ignore[attr-defined]
            return "HTTP"
        if HTTPResponse and pkt.haslayer(HTTPResponse):  # type: ignore[attr-defined]
            return "HTTP"
        if HTTP and pkt.haslayer(HTTP):  # type: ignore[attr-defined]
            return "HTTP"
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

    def _stringify_value(value: Any) -> str:
        if isinstance(value, bytes):
            if not value:
                return "(empty)"
            snippet = value[:64]
            hexed = snippet.hex()
            suffix = "…" if len(value) > len(snippet) else ""
            return f"0x{hexed}{suffix} ({len(value)} bytes)"
        if isinstance(value, Packet):
            return value.summary()
        if isinstance(value, (list, tuple)):
            return ", ".join(_stringify_value(item) for item in value)
        return str(value)

    def _layer_details(packet_obj: Packet, frame_no: int) -> List[Dict[str, Any]]:
        details: List[Dict[str, Any]] = []
        # First entry mimics Wireshark's frame summary
        details.append(
            {
                "label": f"Frame {frame_no}",
                "fields": [
                    {"name": "Captured length", "value": f"{len(packet_obj)} bytes"},
                    {"name": "Protocols", "value": "/".join(packet_obj.command().split("/"))},
                ],
            }
        )

        current = packet_obj
        visited: set[int] = set()
        while current and not isinstance(current, NoPayload):
            label = getattr(current, "name", current.__class__.__name__)
            fields = []
            for key, value in getattr(current, "fields", {}).items():
                fields.append({"name": key, "value": _stringify_value(value)})
            details.append({"label": label, "fields": fields})

            payload = getattr(current, "payload", None)
            if not payload or isinstance(payload, NoPayload):
                break
            if id(payload) in visited:
                break
            visited.add(id(payload))
            current = payload

        return details

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
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 and packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst

        proto = _proto_label(packet)
        proto_counter[proto] += 1

        if src:
            talkers[src] += 1
        if dst:
            targets[dst] += 1
        if src or dst:
            pairs[(src, dst)] += 1

        dst_port = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        if dst_port is not None:
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
            "frame_no": captured,
        }
        if include_hex:
            sample_entry["hex"] = hexdump_fn(packet, dump=True)

        sample_entry["layers"] = _layer_details(packet, captured)

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
