from __future__ import annotations
from typing import Any, Dict, List, Optional
import json
import xml.etree.ElementTree as ET
from collections import Counter


# -------- Bandit JSON -> readable dict --------
def parse_bandit_json(stdout: str) -> Dict[str, Any]:
    data = {}
    try:
        data = json.loads(stdout or "{}")
    except Exception:
        # Not JSON (or empty). Return minimal structure.
        return {
            "summary": {"errors": ["Invalid Bandit JSON"], "totals": {}},
            "findings": [],
            "raw": stdout or "",
        }

    # Extract totals and errors
    errors = []
    for e in data.get("errors", []) or []:
        filename = e.get("filename", "?")
        reason = e.get("reason", "Unknown error")
        errors.append(f"{filename}: {reason}")

    totals = data.get("metrics", {}).get("_totals", {}) or {}

    # Extract findings
    findings: List[Dict[str, Any]] = []
    for r in data.get("results", []) or []:
        findings.append({
            "file": r.get("filename"),
            "line": r.get("line_number"),
            "code_snippet": r.get("code", "").strip(),
            "severity": r.get("issue_severity", "UNDEFINED"),
            "confidence": r.get("issue_confidence", "UNDEFINED"),
            "msg": r.get("issue_text", ""),
            "test_id": r.get("test_id"),
            "test_name": r.get("test_name"),
            "cwe": (r.get("issue_cwe") or {}).get("id"),
            "more_info": r.get("more_info"),
        })

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNDEFINED": 0}
    for f in findings:
        sev = (f["severity"] or "UNDEFINED").upper()
        if sev not in severity_counts:
            severity_counts["UNDEFINED"] += 1
        else:
            severity_counts[sev] += 1

    summary = {
        "errors": errors,
        "totals": totals,
        "severity_counts": severity_counts,
        "generated_at": data.get("generated_at"),
    }

    return {
        "summary": summary,
        "findings": findings,
        "raw": data,  # keep parsed object
    }


# -------- Nmap XML -> readable dict --------
def _text_or_none(el: Optional[ET.Element]) -> Optional[str]:
    return el.text if el is not None else None


def parse_nmap_xml(stdout: str) -> Dict[str, Any]:
    """
    Parse Nmap XML (as emitted with `-oX -`) into a friendly dict:
    {
      "summary": { "hosts_total": int, "hosts_up": int, "scanned_at": str, "top_ports": [...] },
      "hosts": [ { "addresses":[...], "hostnames":[...], "status":"up|down", "ports":[...] }, ... ],
      "raw_xml": stdout
    }
    """
    result: Dict[str, Any] = {"summary": {}, "hosts": [], "raw_xml": stdout}
    if not stdout or "<nmaprun" not in stdout:
        # Not XML (fallback; return raw)
        return {"summary": {"error": "not_xml"}, "hosts": [], "raw_xml": stdout}

    try:
        root = ET.fromstring(stdout)
    except Exception as e:
        return {"summary": {"error": f"xml_parse_error: {e}"}, "hosts": [], "raw_xml": stdout}

    scanned_at = root.get("startstr")
    result["summary"]["scanned_at"] = scanned_at

    hosts: List[Dict[str, Any]] = []
    port_counter: Counter[str] = Counter()
    hosts_total = 0
    hosts_up = 0

    for host_el in root.findall("host"):
        hosts_total += 1
        h: Dict[str, Any] = {"addresses": [], "hostnames": [], "status": None, "ports": []}

        # status
        status_el = host_el.find("status")
        if status_el is not None:
            h["status"] = status_el.get("state")
            if h["status"] == "up":
                hosts_up += 1

        # addresses
        for a in host_el.findall("address"):
            h["addresses"].append({"addr": a.get("addr"), "addrtype": a.get("addrtype")})

        # hostnames
        hn_el = host_el.find("hostnames")
        if hn_el is not None:
            for nm in hn_el.findall("hostname"):
                n = nm.get("name")
                if n:
                    h["hostnames"].append(n)

        # ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol")
                portnum = int(p.get("portid"))
                state_el = p.find("state")
                service_el = p.find("service")
                state = state_el.get("state") if state_el is not None else None
                reason = state_el.get("reason") if state_el is not None else None
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                port_obj = {
                    "port": portnum,
                    "proto": proto,
                    "state": state,
                    "reason": reason,
                    "service": service,
                    "product": product,
                    "version": version,
                }
                h["ports"].append(port_obj)
                if state == "open":
                    port_counter[f"{proto}/{portnum}"] += 1

        hosts.append(h)

    top_ports = [{"port": p, "count": c} for p, c in port_counter.most_common(10)]

    result["summary"].update({
        "hosts_total": hosts_total,
        "hosts_up": hosts_up,
        "top_ports": top_ports,
    })
    result["hosts"] = hosts
    return result
