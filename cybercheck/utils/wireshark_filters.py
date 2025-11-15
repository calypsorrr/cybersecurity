"""Helpers that derive actionable Wireshark display filters from PCAP stats."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Tuple


SENSITIVE_PROTOCOL_FILTERS = {
    "DNS": ("dns", "Highlight unusual domain lookups or tunneling attempts."),
    "ICMP": ("icmp", "Surface ping sweeps or covert ICMP tunnels."),
    "ARP": ("arp", "Catch gratuitous ARP replies or spoofing attempts."),
    "IPv6": ("ipv6", "Flag IPv6 traffic observed in mostly IPv4 networks."),
}


HIGH_VALUE_PORTS = {
    21: "FTP control",  # clear-text credentials
    22: "SSH remote access",
    23: "Telnet remote access",
    25: "SMTP mail relay",
    53: "DNS infrastructure",
    80: "HTTP web traffic",
    110: "POP3 mailbox access",
    143: "IMAP mailbox access",
    389: "LDAP directory services",
    445: "SMB file sharing",
    464: "Kerberos kpasswd",
    500: "IKE/IPsec negotiation",
    1433: "MSSQL database",
    1521: "Oracle database",
    3306: "MySQL database",
    3389: "RDP remote desktop",
    5900: "VNC remote control",
}


def _valid_ip_clause(address: str) -> Optional[Tuple[str, str]]:
    """Return the Wireshark field/operator for an IP address if valid."""

    if not address or address == "?":
        return None
    try:
        parsed = ip_address(address)
    except ValueError:
        return None

    field = "ipv6.addr" if parsed.version == 6 else "ip.addr"
    return field, str(parsed)


def _port_clause(label: str) -> Optional[Tuple[str, int]]:
    if not label or ":" not in label:
        return None
    proto, raw_port = label.split(":", 1)
    if not raw_port.isdigit():
        return None
    port = int(raw_port)
    if port not in HIGH_VALUE_PORTS:
        return None

    proto_upper = proto.upper()
    if proto_upper == "TCP":
        field = "tcp.port"
    elif proto_upper == "UDP":
        field = "udp.port"
    else:
        return None
    return field, port


def build_filter_suggestion(report: Dict[str, Any] | None) -> Dict[str, Any]:
    """Create a Wireshark display filter suggestion based on report stats."""

    if not report:
        return {
            "display_filter": "tcp || udp || icmp",
            "reasons": ["Fallback filter applied because no capture statistics were available."],
        }

    clauses: List[str] = []
    reasons: List[str] = []

    # Prioritize top talkers/targets to help zero-in on the busiest hosts.
    for collection in (report.get("talkers") or [], report.get("targets") or []):
        for entry in collection[:2]:
            clause_data = _valid_ip_clause(entry.get("label", ""))
            if not clause_data:
                continue
            field, addr = clause_data
            clause = f"{field} == {addr}"
            if clause in clauses:
                continue
            clauses.append(clause)
            count = entry.get("count")
            if count:
                reasons.append(f"Host {addr} observed in {int(count)} packets. Focus traffic for triage.")
            else:
                reasons.append(f"Host {addr} appeared among the busiest peers.")

    # Add sensitive protocol toggles.
    for entry in report.get("protocols") or []:
        proto = entry.get("label", "").upper()
        advice = SENSITIVE_PROTOCOL_FILTERS.get(proto)
        if not advice:
            continue
        clause, rationale = advice
        if clause not in clauses:
            clauses.append(clause)
            reasons.append(rationale)

    # Look for high-value service ports.
    for entry in report.get("ports") or []:
        result = _port_clause(entry.get("label", ""))
        if not result:
            continue
        field, port = result
        clause = f"{field} == {port}"
        if clause in clauses:
            continue
        clauses.append(clause)
        reasons.append(f"{HIGH_VALUE_PORTS[port]} observed on {field}. Inspect related sessions.")

    if not clauses:
        clauses = ["tcp", "udp", "icmp", "dns"]
        reasons.append(
            "Defaulted to core transport/display filters because no dominant hosts or protocols were detected."
        )

    return {"display_filter": " || ".join(clauses), "reasons": reasons}

