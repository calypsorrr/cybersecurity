from __future__ import annotations

from collections import Counter, OrderedDict
import json
import secrets
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from tempfile import NamedTemporaryFile

from cybercheck.config import SECRET_KEY, NMAP_PROFILES
from cybercheck.utils.auth import (
    authenticate_user,
    bootstrap_admin,
    current_user,
    require_active_session,
    require_role,
)
from cybercheck.scanners import nmap_scan, nikto_scan, scapy_ping_scan
from cybercheck.scanners import run_ettercap
from cybercheck.scanners.extended_tools import (
    zap_scan,
    gitleaks_scan,
    trufflehog_scan,
    trivy_scan,
    grype_scan,
    checkov_scan,
    volatility_inspect,
    spiderfoot_scan,
)
from cybercheck.scanners.runner import run_tool
from cybercheck.models.db import (
    fetch_asset_inventory,
    fetch_control_mappings,
    fetch_findings,
    fetch_last_runs,
)
from cybercheck.utils.parsers import parse_bandit_json  # Bandit -> readable report
from cybercheck.utils.reporting import build_control_report
from cybercheck.utils.monitor import network_monitor
from cybercheck.utils.alerts import alert_pipeline
from cybercheck.utils.scheduler import scan_scheduler
from cybercheck.utils.firewall_regression import (
    collect_expectations,
    run_firewall_matrix,
    run_firewall_pentest,
)
from cybercheck.utils.detection_validation import register_validation, replay_pcap, record_result
from cybercheck.utils.capture import analyze_pcap_file, extract_interesting_packets
from cybercheck.utils.background_sniffer import background_sniffer
from cybercheck.utils.background_spiderfoot import (
    SPIDERFOOT_CAPABILITIES,
    SPIDERFOOT_EVENT_GRAPH,
    background_spiderfoot,
)
from cybercheck.utils.inspector import analyze_email_text, analyze_uploaded_file
from cybercheck.utils.pcap_paths import resolve_pcap_output_path

try:
    from datetime import UTC
except ImportError:  # pragma: no cover - Python <3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

BASE_DIR = Path(__file__).resolve().parent

WIRESHARK_CACHE_LIMIT = 6
WIRESHARK_RUN_CACHE: OrderedDict[str, Dict[str, Any]] = OrderedDict()

SPIDERFOOT_PRESETS = [
    {
        "value": "auto",
        "label": "Smart defaults",
        "modules": "",
        "description": "Let SpiderFoot pick modules based on the target type.",
    },
    {
        "value": "basic",
        "label": "Basic footprint (faster)",
        "modules": "sfp_dnsresolve,sfp_dnsbrute,sfp_rdap",
        "description": "Quick DNS/WHOIS style footprint without heavy third-party calls.",
    },
    {
        "value": "breach",
        "label": "Infra + breach signals",
        "modules": "sfp_dnsresolve,sfp_rdap,sfp_abusech,sfp_shodan,sfp_haveibeenpwned",
        "description": "Adds breach and reputation lookups to the basic footprint.",
    },
    {
        "value": "crawl",
        "label": "Web crawl + metadata",
        "modules": "sfp_spider,sfp_httpheaders,sfp_htmlmeta,sfp_email",
        "description": "Requests + BeautifulSoup style crawling with URL discovery, headers, cookies, JS, and email scraping.",
    },
    {
        "value": "apis",
        "label": "Threat intel APIs",
        "modules": "sfp_shodan,sfp_virustotal,sfp_haveibeenpwned,sfp_abuseipdb,sfp_censys",
        "description": "Shodan, VirusTotal, HIBP, AbuseIPDB, and Censys enrichments for infra and breaches.",
    },
    {
        "value": "all",
        "label": "All modules (slow)",
        "modules": "all",
        "description": "SpiderFoot will attempt every module it knows about.",
    },
    {
        "value": "custom",
        "label": "Custom list",
        "modules": "",
        "description": "Bring your own comma-separated modules.",
    },
]


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return False
    return text in {"1", "true", "yes", "on"}


def _slugify_target(value: str) -> str:
    """Return a filesystem-friendly token for naming artifacts."""

    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)
    cleaned = cleaned.strip("._")
    return cleaned or "target"


ETTERCAP_MITM_METHODS = [
    {
        "value": "arp",
        "label": "ARP poisoning (LAN)",
        "summary": "Classic gateway spoofing between target hosts on the same broadcast domain.",
    },
    {
        "value": "arp:remote",
        "label": "ARP remote",
        "summary": "Like ARP poisoning but relays packets between distant segments; slower but flexible.",
    },
    {
        "value": "icmp",
        "label": "ICMP redirect",
        "summary": "Rewrite ICMP redirects to pull traffic through your interface.",
    },
    {
        "value": "dhcp",
        "label": "DHCP spoof",
        "summary": "Answer DHCP queries with crafted options to steer victims.",
    },
]

ETTERCAP_CAPABILITIES = [
    {
        "title": "Unified sniffing",
        "body": "Mirror the <code>ettercap -T -q -i iface</code> workflow with optional filters, plugins and capture files.",
    },
    {
        "title": "MITM pivot",
        "body": "Launch ARP, ICMP or DHCP based attacks without leaving the web console. Targets use the familiar /target/ notation.",
    },
    {
        "title": "Host discovery sweeps",
        "body": "Run remote ARP poisoning against CIDR ranges to quickly enumerate active clients inside the engagement scope.",
    },
    {
        "title": "Custom CLI wrapper",
        "body": "Feed any Ettercap arguments you'd normally run on Linux and capture stdout/stderr plus logs in the dashboard.",
    },
]

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = SECRET_KEY


def _remember_wireshark_analysis(analysis: Dict[str, Any]) -> str:
    """Store Wireshark results temporarily so they can be rendered elsewhere."""

    run_id = secrets.token_urlsafe(8)
    WIRESHARK_RUN_CACHE[run_id] = analysis

    while len(WIRESHARK_RUN_CACHE) > WIRESHARK_CACHE_LIMIT:
        WIRESHARK_RUN_CACHE.popitem(last=False)

    return run_id


def _get_wireshark_analysis(run_id: str) -> Optional[Dict[str, Any]]:
    return WIRESHARK_RUN_CACHE.get(run_id)


# ---------- Build preset list of project targets (for the dropdown) ----------
def list_project_targets(max_depth: int = 2) -> list[str]:
    """
    Return a list of relative paths (dirs and .py files) under the project
    to show in the dropdown. Skips noisy/irrelevant folders.
    """
    root = BASE_DIR
    excludes = {
        ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".git", "node_modules", "logs", "static/vendor"
    }
    results: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)

        # depth filter
        if len(rel_dir.parts) > max_depth:
            dirnames[:] = []
            continue

        # prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if str(Path(rel_dir, d)) not in excludes and d not in excludes]

        # Include the directory itself (except root) if it's not excluded
        if rel_dir != Path(".") and str(rel_dir) not in excludes:
            results.append(str(rel_dir).replace("\\", "/"))

        # Include python files at this level
        for f in filenames:
            if f.endswith(".py"):
                p = str(Path(rel_dir, f)).replace("\\", "/")
                if not any(p.startswith(ex + "/") or p == ex for ex in excludes):
                    results.append(p)

    # De-dup and sort; prefer directories first
    dirs = sorted([p for p in results if not p.endswith(".py")])
    files = sorted([p for p in results if p.endswith(".py")])
    return dirs + files
# ---------------------------------------------------------------------------


def _parse_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        fixed = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(fixed)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def _format_timestamp(dt: datetime | None) -> str:
    if not dt:
        return "—"
    try:
        return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:  # pragma: no cover - safety guard
        return dt.strftime("%Y-%m-%d %H:%M")


@app.route("/")
def index():
    runs = fetch_last_runs(20)
    assets = fetch_asset_inventory()
    controls = fetch_control_mappings()
    findings = fetch_findings(5)
    presets = list_project_targets()
    active_tools = {"nmap", "nikto", "scapy"}
    active_runs = [r for r in runs if (r["tool"] or "").lower() in active_tools]
    last_active = _parse_timestamp(active_runs[0]["finished_at"]) if active_runs else None
    open_findings = sum((row["open_findings"] or 0) for row in assets)
    uncovered_controls = [c for c in controls if (c["asset_total"] or 0) == 0]
    metrics = {
        "total_runs": len(runs),
        "active_runs": len(active_runs),
        "last_active_finished": _format_timestamp(last_active),
        "asset_count": len(assets),
        "open_findings": open_findings,
        "control_gaps": len(uncovered_controls),
    }
    control_report = build_control_report(20)
    return render_template(
        "index.html",
        runs=runs,
        assets=assets,
        controls=controls,
        findings=findings,
        nmap_profiles=list(NMAP_PROFILES.keys()),
        scan_presets=presets,
        metrics=metrics,
        control_report=control_report,
        active_page="home",
    )


# ---- Authentication and RBAC ----
@app.route("/auth/bootstrap", methods=["POST"])
def auth_bootstrap():
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password")
    if not password:
        return {"error": "password required"}, 400
    bootstrap_admin(password)
    return {"status": "bootstrapped"}


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return {"error": "missing credentials"}, 400
    if authenticate_user(username, password):
        return {"status": "ok", "user": current_user()}
    return {"error": "invalid credentials"}, 401


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return {"status": "logged out"}


@app.route("/scan-help")
def scan_help():
    scan_guides = [
        {
            "name": "Nmap",
            "tagline": "Network discovery, service fingerprinting & basic vuln probing",
            "summary": "Use Nmap when you need to map hosts, enumerate ports/services, or verify exposure before and after changes.",
            "steps": [
                "Identify the target range (CIDR or host list) and whether host discovery (-sn) is permitted.",
                "Start with a light scan (ping sweep or top ports) to gauge exposure without overwhelming the target.",
                "Enable service/OS detection when you need actionable remediation evidence (versions, banners).",
                "Save command invocations so you can rerun identical profiles after hardening to compare diffs.",
            ],
            "common_flags": [
                {"flag": "-sS", "meaning": "TCP SYN scan (stealthy, fast default)"},
                {"flag": "-sV", "meaning": "Probe services to guess versions"},
                {"flag": "-O", "meaning": "OS fingerprinting (requires root)"},
                {"flag": "-A", "meaning": "Aggressive scan = -sV -O --traceroute + NSE scripts"},
                {"flag": "-T4", "meaning": "Faster timing template for reliable networks"},
                {"flag": "-Pn", "meaning": "Skip host discovery (assume hosts are up)"},
            ],
            "examples": [
                {
                    "label": "Ping sweep / live host discovery",
                    "cmd": "nmap -sn 10.0.0.0/24",
                    "notes": "Use before port scans to understand scope without touching services.",
                },
                {
                    "label": "Top ports & service info",
                    "cmd": "nmap -sS -sV --top-ports 100 192.168.1.50",
                    "notes": "Quick visibility into the most exposed services on a host.",
                },
                {
                    "label": "Full TCP/UDP audit",
                    "cmd": "sudo nmap -p- -sS -sU -O -sV 10.20.30.40",
                    "notes": "Thorough reachability check before/after hardening; slower but comprehensive.",
                },
            ],
            "more_commands": [
                {
                    "label": "Save output for tickets",
                    "cmd": "nmap -sS -sV -oA web-gateway 203.0.113.15",
                },
                {
                    "label": "Scan only web ports",
                    "cmd": "nmap -sS -p 80,443,8443,9443 -sV api.internal",
                },
            ],
        },
        {
            "name": "Nikto",
            "tagline": "Web server misconfiguration & vulnerability sweeps",
            "summary": "Run Nikto when validating HTTP/S attack surface: outdated servers, dangerous files, SSL issues, and known CVEs.",
            "steps": [
                "Confirm the target URLs/ports and whether virtual hosts or proxies are in use.",
                "Run a baseline scan (-h target) to capture general exposure and SSL posture.",
                "Add tuning flags (e.g., 0 4 9) to prioritize file disclosure and injection tests when triaging.",
                "Export results (JSON/HTML) to attach to tickets or CI pipelines.",
            ],
            "common_flags": [
                {"flag": "-h", "meaning": "Target host, IP, or URL"},
                {"flag": "-p", "meaning": "Port list (e.g. 80,443,8080)"},
                {"flag": "-ssl", "meaning": "Force SSL if auto-detect fails"},
                {"flag": "-Tuning", "meaning": "Select test families (0=File, 4=Injection, 9=Misc)"},
                {"flag": "-Plugins", "meaning": "Enable/disable specific plugin modules"},
                {"flag": "-output", "meaning": "Write findings to file (JSON, CSV, HTML)"},
            ],
            "examples": [
                {
                    "label": "Standard HTTPS assessment",
                    "cmd": "nikto -h https://app.internal.example",
                    "notes": "Covers 6k+ checks, SSL configuration, dangerous files, default creds.",
                },
                {
                    "label": "Multiple ports + tuning",
                    "cmd": "nikto -h 10.1.5.15 -p 80,8080 -Tuning x 9",
                    "notes": "Focus on XSS + misc tests when triaging web proxy clusters.",
                },
                {
                    "label": "Report for ticket attachment",
                    "cmd": "nikto -h https://prod.example -output prod-nikto.json",
                    "notes": "Generates JSON for ingestion or compliance evidence.",
                },
            ],
            "more_commands": [
                {
                    "label": "Use a custom user agent",
                    "cmd": "nikto -h https://blog.example -Useragent 'SecOps-Nikto'",
                },
                {
                    "label": "Proxy through Burp/ZAP",
                    "cmd": "nikto -h http://10.0.0.5 -useproxy http://127.0.0.1:8080",
                },
            ],
        },
        {
            "name": "Scapy",
            "tagline": "Packet crafting for validation, troubleshooting & custom probes",
            "summary": "Use Scapy when you need programmable packets: crafting probes, validating firewall rules, or building custom detections.",
            "steps": [
                "Start an interactive Scapy shell with sudo for raw socket access.",
                "Load or craft the protocol layers you need (IP/TCP/UDP/ICMP/Ether).",
                "Send probes with sr()/srp() and inspect replies to validate rules or behaviors.",
                "Capture targeted traffic with sniff() to reproduce alerts or verify tuning.",
            ],
            "common_flags": [
                {"flag": "sr()", "meaning": "Send packets & receive replies (layer 3)"},
                {"flag": "srp()", "meaning": "Layer-2 send/receive (ARP, etc.)"},
                {"flag": "sniff()", "meaning": "Capture packets that match filters"},
                {"flag": "ls(Proto)", "meaning": "List fields of protocol layers"},
                {"flag": "sendpfast", "meaning": "High-speed packet replay"},
            ],
            "examples": [
                {
                    "label": "ARP sweep (like discovery)",
                    "cmd": "srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='10.10.0.0/24'), timeout=2)",
                    "notes": "Confirms which hosts respond on the L2 segment when ICMP is blocked.",
                },
                {
                    "label": "Custom TCP SYN with flags",
                    "cmd": "sr(IP(dst='192.168.1.10')/TCP(dport=[22,443], flags='S'))",
                    "notes": "Validate firewall handling of unusual flag combos or rate limits.",
                },
                {
                    "label": "Packet capture with BPF filter",
                    "cmd": "sniff(filter='tcp port 443', count=50)",
                    "notes": "Troubleshoot TLS handshakes without launching full tcpdump.",
                },
            ],
            "more_commands": [
                {
                    "label": "Trace route with Scapy",
                    "cmd": "sr(IP(dst='8.8.8.8', ttl=(1,16))/ICMP(), timeout=1)",
                },
                {
                    "label": "Replay captured packet quickly",
                    "cmd": "sendpfast(rdpcap('sample.pcap'), iface='eth0')",
                },
            ],
        },
        {
            "name": "OWASP ZAP",
            "tagline": "DAST for web apps and APIs with baseline/full profiles",
            "summary": "Use ZAP when you need active crawling and attack simulation against web apps or OpenAPI-described APIs.",
            "steps": [
                "Choose the profile: baseline (passive), full (active), or API with the OpenAPI spec provided.",
                "Point ZAP at an authenticated or staging target when possible to reduce false positives.",
                "Let the spider/AJAX spider complete before reviewing alerts for authentication and input handling.",
                "Export the HTML/JSON report and log the alert IDs you suppress for repeatability.",
            ],
            "common_flags": [
                {"flag": "-t", "meaning": "Target URL"},
                {"flag": "-u", "meaning": "Context/user auth file for authenticated scans"},
                {"flag": "-J", "meaning": "Output JSON report"},
                {"flag": "-r", "meaning": "Output HTML report"},
                {"flag": "-z", "meaning": "Overrides for AJAX spider or policy toggles"},
            ],
            "examples": [
                {
                    "label": "Baseline passive crawl",
                    "cmd": "zap-baseline.py -t https://staging.example.com -r zap-baseline.html",
                    "notes": "Good first pass to catch missing security headers and basic issues without active attacks.",
                },
                {
                    "label": "API scan with OpenAPI",
                    "cmd": "zap-api-scan.py -t https://api.example.com/openapi.json -f openapi -r zap-api.html",
                    "notes": "Exercises API endpoints and reports auth/input weaknesses.",
                },
                {
                    "label": "Full active scan",
                    "cmd": "zap-full-scan.py -t https://app.example.com -r zap-full.html",
                    "notes": "Runs active attacks; schedule during maintenance windows.",
                },
            ],
            "more_commands": [
                {
                    "label": "Route traffic through proxy",
                    "cmd": "zap-baseline.py -t https://app -P http://127.0.0.1:8080",
                },
                {
                    "label": "Authenticated context",
                    "cmd": "zap-full-scan.py -t https://app --auth login.context -r zap-auth.html",
                },
            ],
        },
        {
            "name": "Ettercap",
            "tagline": "Layer-2 interception, MITM testing, and credential harvesting",
            "summary": "Use Ettercap in controlled lab segments to validate NAC, DHCP snooping, and detection of ARP poisoning attempts.",
            "steps": [
                "Ensure you are on an authorized, isolated network segment; enable IP forwarding if relaying traffic.",
                "Choose targets (single host, range, or gateway) and select ARP poisoning or passive sniffing mode.",
                "Start unified sniffing and watch for credentials or cleartext protocols in the log window.",
                "Stop the attack and restore ARP tables after testing to avoid lingering disruption.",
            ],
            "common_flags": [
                {"flag": "-T", "meaning": "Text-only UI"},
                {"flag": "-M arp:remote", "meaning": "Enable ARP MITM between targets"},
                {"flag": "-i", "meaning": "Interface to bind (e.g., eth0)"},
                {"flag": "-w", "meaning": "Write captured packets to pcap"},
                {"flag": "-L", "meaning": "Log credentials to file"},
            ],
            "examples": [
                {
                    "label": "ARP poison two hosts",
                    "cmd": "sudo ettercap -T -M arp:remote /10.10.0.5/ /10.10.0.10/",
                    "notes": "Validates whether NAC/IDS blocks L2 MITM attempts.",
                },
                {
                    "label": "MITM gateway and subnet",
                    "cmd": "sudo ettercap -T -M arp:remote /10.10.0.1/ /10.10.0.0-255/",
                    "notes": "Useful for lab validation of DHCP snooping/DAI protections.",
                },
                {
                    "label": "Capture creds to file",
                    "cmd": "sudo ettercap -T -M arp:remote -L creds.log /victim/ /gateway/",
                    "notes": "Stores intercepted credentials for forensic review in test environments.",
                },
            ],
            "more_commands": [
                {
                    "label": "Write packets for later analysis",
                    "cmd": "sudo ettercap -T -M arp:remote -w ettercap.pcap /host/ /gw/",
                },
                {
                    "label": "Use a specific network interface",
                    "cmd": "sudo ettercap -T -i eth1 -M arp:remote /10.0.0.0-50/ /router/",
                },
            ],
        },
        {
            "name": "Secrets & supply chain",
            "tagline": "Gitleaks/TruffleHog for secrets, Trivy/Grype for images, Checkov for IaC",
            "summary": "Use these when validating repos and build artifacts before release to catch exposed credentials, vulnerable base images, and misconfigured infrastructure code.",
            "steps": [
                "Run secret scanners (Gitleaks or TruffleHog) on the repo to block committed keys or tokens.",
                "Generate or load an SBOM, then scan images with Trivy/Grype to flag vulnerable packages.",
                "Lint IaC (Terraform/CloudFormation/K8s) with Checkov to catch misconfigurations before deploy.",
                "Record the scanner versions and baselines so CI jobs can diff and gate merges consistently.",
            ],
            "common_flags": [
                {"flag": "gitleaks detect --source .", "meaning": "Scan current repo for secrets"},
                {"flag": "trufflehog filesystem .", "meaning": "Deep entropy+regex search for secrets"},
                {"flag": "trivy image", "meaning": "Scan container images for CVEs and misconfig"},
                {"flag": "grype <image>", "meaning": "Alternative image scanner using Syft SBOM"},
                {"flag": "checkov -d .", "meaning": "Scan IaC directory for policy violations"},
            ],
            "examples": [
                {
                    "label": "Repo secret sweep",
                    "cmd": "gitleaks detect --source . --report-path gitleaks.json",
                    "notes": "Use in pre-commit or CI to prevent leaking credentials.",
                },
                {
                    "label": "Container CVE scan",
                    "cmd": "trivy image --scanners vuln,secret registry.example.com/app:latest",
                    "notes": "Combines vuln + secret checks before pushing to production registries.",
                },
                {
                    "label": "IaC posture check",
                    "cmd": "checkov -d infrastructure/terraform -o json",
                    "notes": "Exports findings for dashboards and merge gating.",
                },
            ],
            "more_commands": [
                {
                    "label": "Scan with Grype using SBOM",
                    "cmd": "syft registry.example.com/app:latest -o json > sbom.json && grype sbom:sbom.json",
                },
                {
                    "label": "TruffleHog git history",
                    "cmd": "trufflehog git --json . > trufflehog-history.json",
                },
            ],
        },
    ]

    decision_matrix = [
        {
            "task": "Map unknown network segment / baseline services",
            "recommended": "Nmap (start with -sn to find hosts, escalate to -sS -sV for services)",
            "why": "Fast discovery + automated service fingerprinting across many hosts.",
        },
        {
            "task": "Validate web server hardening / find exposed files",
            "recommended": "Nikto (-h target -ssl -Tuning 0 4 9)",
            "why": "Purpose-built HTTP checklist catches outdated software and dangerous URIs.",
        },
        {
            "task": "DAST against staging web apps or APIs",
            "recommended": "OWASP ZAP baseline/full or API profile with spec",
            "why": "Combines crawling with active checks to surface auth, input, and policy gaps.",
        },
        {
            "task": "Test firewall rules or reproduce IDS alerts with crafted packets",
            "recommended": "Scapy (sr/srp/sendp) with custom layers",
            "why": "Lets you build packets by hand and observe responses in real time.",
        },
        {
            "task": "Simulate ARP spoofing to validate NAC/DAI",
            "recommended": "Ettercap (-T -M arp:remote /victim/ /gateway/)",
            "why": "Exercises L2 protections and detection with reversible, controlled MITM.",
        },
        {
            "task": "Continuous ping/port monitoring for outages",
            "recommended": "Use built-in Scapy ping preset in CyberCheck",
            "why": "Lightweight and scriptable; integrate with dashboards.",
        },
        {
            "task": "Service validation after remediation",
            "recommended": "Re-run the same Nmap profile + Nikto (if web) to compare diffs",
            "why": "Deterministic scans provide evidence that findings were addressed.",
        },
        {
            "task": "Pre-release repo/image/IaC hygiene",
            "recommended": "Secrets & supply chain suite (Gitleaks/Trivy/Checkov)",
            "why": "Catches embedded secrets, vulnerable packages, and misconfigurations before deploy.",
        },
    ]

    return render_template(
        "scan_help.html",
        active_page="scan_help",
        guides=scan_guides,
        decision_matrix=decision_matrix,
        nmap_profiles=NMAP_PROFILES,
    )


@app.route("/firewall")
@app.route("/security-ops")
def firewall():
    user = current_user()
    return render_template("firewall.html", user=user, active_page="firewall")


@app.route("/payload-inspector", methods=["GET", "POST"])
def payload_inspector():
    results = []

    if request.method == "POST":
        uploaded = request.files.get("payload_file")
        email_raw = (request.form.get("email_raw") or "").strip()

        if uploaded and uploaded.filename:
            results.append(analyze_uploaded_file(uploaded.filename, uploaded.read()))

        if email_raw:
            results.append(analyze_email_text(email_raw))

        if not results:
            flash("Upload a file or paste an email to inspect.", "warning")
            return redirect(url_for("payload_inspector"))

        risk_rank = {"info": 0, "medium": 1, "high": 2}
        highest_risk = max((risk_rank.get(r.get("risk_level", "info"), 0) for r in results), default=0)
        if highest_risk >= 2:
            flash("Potentially malicious traits detected.", "danger")
        elif highest_risk == 1:
            flash("Review the findings below before trusting this payload.", "warning")
        else:
            flash("No obvious threats detected, but manual verification is recommended.", "info")

    return render_template(
        "inspector.html",
        active_page="inspector",
        results=results,
    )


@app.route("/wireshark")
def wireshark_console():
    default_state = {
        "user": "pcap-operator",
        "include_hex": False,
    }
    return render_template(
        "wireshark.html",
        active_page="wireshark",
        form_state=default_state,
        analysis=None,
    )


@app.route("/wireshark/analyze", methods=["POST"])
def wireshark_analyze():
    token = request.form.get("engagement_token")
    if not require_active_session(token or ""):
        flash("Valid engagement token required for PCAP reviews.", "danger")
        return redirect(url_for("wireshark_console"))

    uploaded = request.files.get("pcap_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a PCAP file to analyze.", "warning")
        return redirect(url_for("wireshark_console"))

    user = (request.form.get("user") or "pcap-operator").strip() or "pcap-operator"
    include_hex = request.form.get("include_hex", "0") == "1"
    original_name = Path(uploaded.filename).name

    temp_path: Optional[Path] = None
    try:
        with NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
            uploaded.save(temp_file.name)
            temp_path = Path(temp_file.name)

        analysis = analyze_pcap_file(
            user=user,
            file_path=temp_path,
            include_hex=include_hex,
            original_name=original_name,
        )
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)

    run_id: Optional[str] = None
    if analysis.get("report"):
        run_id = _remember_wireshark_analysis(analysis)
        analysis["run_id"] = run_id

    returncode = analysis.get("returncode", 0)
    summary = (analysis.get("report") or {}).get("summary") or {}
    packet_count = summary.get("captured", 0)
    label = summary.get("source_label", original_name)

    if returncode == 0:
        flash(f"Analyzed {packet_count} packets from {label}.", "success")
    elif returncode == 1 and not analysis.get("stderr"):
        flash("The supplied PCAP did not contain any packets.", "warning")
    else:
        error = analysis.get("stderr") or "Failed to parse the uploaded PCAP file."
        flash(error, "danger")

    form_state = {
        "user": user,
        "include_hex": include_hex,
    }

    return render_template(
        "wireshark.html",
        active_page="wireshark",
        form_state=form_state,
        analysis=analysis,
    )


@app.route("/wireshark/full/<run_id>")
def wireshark_full(run_id: str):
    analysis = _get_wireshark_analysis(run_id)
    if not analysis:
        flash("That capture report has expired. Re-upload the PCAP to view it again.", "warning")
        return redirect(url_for("wireshark_console"))

    report = analysis.get("report") or {}
    summary = report.get("summary") or {}
    samples = report.get("all_samples") or []

    return render_template(
        "wireshark_full.html",
        active_page="wireshark",
        analysis=analysis,
        report=report,
        summary=summary,
        samples=samples,
        run_id=run_id,
    )


@app.route("/wireshark/cleanup/<run_id>")
def wireshark_cleanup(run_id: str):
    analysis = _get_wireshark_analysis(run_id)
    if not analysis:
        flash("That capture report has expired. Re-upload the PCAP to view it again.", "warning")
        return redirect(url_for("wireshark_console"))

    report = analysis.get("report") or {}
    summary = report.get("summary") or {}
    samples = extract_interesting_packets(report)

    return render_template(
        "wireshark_cleanup.html",
        active_page="wireshark",
        analysis=analysis,
        report=report,
        summary=summary,
        samples=samples,
        run_id=run_id,
    )


@app.route("/spiderfoot", methods=["GET", "POST"])
def spiderfoot_console():
    """Dedicated SpiderFoot console for OSINT-style lookups."""

    run_id = request.args.get("run_id") or (request.form.get("run_id") or "").strip()
    run_status: Dict[str, Any] | None = background_spiderfoot.status(run_id)
    target_value = ""
    target_type = request.form.get("target_type", "domain")
    modules_raw = (request.form.get("spiderfoot_modules") or "").strip()
    user = (request.form.get("user") or "operator").strip() or "operator"
    preset = request.form.get("spiderfoot_profile", "auto")

    lookup_types = [
        {"value": "ip", "label": "IP address", "example": "8.8.8.8"},
        {"value": "domain", "label": "Domain or sub-domain", "example": "example.com"},
        {"value": "hostname", "label": "Hostname", "example": "web-01.internal"},
        {"value": "cidr", "label": "Network subnet (CIDR)", "example": "10.10.0.0/24"},
        {"value": "asn", "label": "ASN", "example": "AS15169"},
        {"value": "email", "label": "E-mail address", "example": "user@example.com"},
        {"value": "phone", "label": "Phone number", "example": "+1-555-0100"},
        {"value": "username", "label": "Username", "example": "jdoe"},
        {"value": "person", "label": "Person's name", "example": "Jane Doe"},
        {"value": "bitcoin", "label": "Bitcoin address", "example": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"},
    ]

    if request.method == "POST":
        target_value = (request.form.get("target_value") or "").strip()
        if not target_value:
            flash("Target is required for SpiderFoot lookups.", "danger")
        else:
            preset_def = next((p for p in SPIDERFOOT_PRESETS if p["value"] == preset), None)
            if preset_def and preset_def["value"] != "custom":
                modules_raw = preset_def.get("modules", "")

            modules = [m.strip() for m in modules_raw.split(",") if m.strip()]

            try:
                run_info = background_spiderfoot.start(
                    user=user,
                    target=target_value,
                    target_type=target_type,
                    modules=modules,
                )
                flash("SpiderFoot is running in the background. Live output will stream below.", "success")
                run_id = run_info.get("run_id")
                run_status = background_spiderfoot.status(run_id)
            except Exception as exc:  # pragma: no cover - relies on system binary
                flash(f"Unable to start SpiderFoot: {exc}", "danger")

    return render_template(
        "spiderfoot.html",
        run_status=run_status,
        run_id=run_id,
        target_value=target_value,
        target_type=target_type,
        lookup_types=lookup_types,
        modules_raw=modules_raw,
        presets=SPIDERFOOT_PRESETS,
        active_preset=preset,
        user=user,
        spiderfoot_capabilities=SPIDERFOOT_CAPABILITIES,
        event_graph=SPIDERFOOT_EVENT_GRAPH,
        title="SpiderFoot OSINT",
        active_page="spiderfoot",
    )


@app.route("/spiderfoot/status/<run_id>")
def spiderfoot_status(run_id: str):
    data = background_spiderfoot.status(run_id)
    if not data:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(data)


@app.route("/spiderfoot/stop/<run_id>", methods=["POST"])
def spiderfoot_stop(run_id: str):
    stopped = background_spiderfoot.stop(run_id)
    if not stopped:
        return jsonify({"error": "Run not found or already finished"}), 404
    return jsonify({"status": "stopped"})


@app.route("/spiderfoot/report/<run_id>")
def spiderfoot_report(run_id: str):
    """Return a structured JSON report for a SpiderFoot run."""

    report = background_spiderfoot.report(run_id)
    if not report:
        return jsonify({"error": "Run not found"}), 404

    payload = json.dumps(report, indent=2)
    response = app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = f"attachment; filename=spiderfoot-{run_id}.json"
    return response


@app.route("/ettercap")
def ettercap_console():
    return render_template(
        "ettercap.html",
        active_page="ettercap",
        mitm_methods=ETTERCAP_MITM_METHODS,
        capabilities=ETTERCAP_CAPABILITIES,
    )


@app.route("/run_ettercap", methods=["POST"])
def run_ettercap_route():
    token = request.form.get("engagement_token")
    if not require_active_session(token or ""):
        flash("Invalid or missing engagement token.", "danger")
        return redirect(url_for("ettercap_console"))

    operation = (request.form.get("operation") or "sniff").strip() or "sniff"
    interface = (request.form.get("interface") or "").strip()
    user = (request.form.get("user") or "operator").strip() or "operator"
    quiet = request.form.get("quiet", "0") == "1"
    text_mode = request.form.get("text_mode", "0") == "1"
    plugin = (request.form.get("plugin") or "").strip() or None
    filter_script = (request.form.get("filter_script") or "").strip() or None
    log_file = (request.form.get("log_file") or "").strip() or None
    pcap_file_input = (request.form.get("pcap_file") or "").strip() or None
    target_a = (request.form.get("target_a") or "").strip() or None
    target_b = (request.form.get("target_b") or "").strip() or None
    mitm_method = (request.form.get("mitm_method") or "").strip() or None
    extra_args_raw = (request.form.get("extra_args") or "").strip()
    custom_args_raw = (request.form.get("custom_args") or "").strip()

    if not interface:
        flash("Interface is required for Ettercap operations.", "danger")
        return redirect(url_for("ettercap_console"))

    if operation == "mitm" and (not target_a or not target_b):
        flash("Target A and Target B are required for MITM runs.", "danger")
        return redirect(url_for("ettercap_console"))

    if operation == "scan" and not target_a:
        flash("Provide at least one network or host list for discovery sweeps.", "danger")
        return redirect(url_for("ettercap_console"))

    extra_args = None
    if extra_args_raw:
        try:
            extra_args = shlex.split(extra_args_raw)
        except ValueError:
            flash("Unable to parse extra arguments. Use space-separated syntax like on Linux.", "danger")
            return redirect(url_for("ettercap_console"))

    custom_args = None
    if operation == "custom":
        if not custom_args_raw:
            flash("Provide Ettercap arguments for custom runs.", "danger")
            return redirect(url_for("ettercap_console"))
        try:
            custom_args = shlex.split(custom_args_raw)
        except ValueError:
            flash("Unable to parse custom Ettercap arguments.", "danger")
            return redirect(url_for("ettercap_console"))

    if pcap_file_input:
        pcap_file = resolve_pcap_output_path(user, pcap_file_input)
    elif operation == "sniff":
        pcap_file = resolve_pcap_output_path(user, None)
    else:
        pcap_file = None

    try:
        res = run_ettercap(
            user=user,
            interface=interface,
            operation=operation,
            quiet=quiet,
            text_mode=text_mode,
            target_a=target_a,
            target_b=target_b,
            mitm_method=mitm_method,
            plugin=plugin,
            filter_script=filter_script,
            log_file=log_file,
            pcap_file=pcap_file,
            extra_args=extra_args,
            custom_args=custom_args,
        )
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ettercap_console"))

    summary = res.get("ettercap_summary")
    title = "Ettercap run"
    if summary and summary.get("operation_label"):
        title = f"Ettercap — {summary['operation_label']}"

    if res.get("returncode", 0) == 0:
        flash("Ettercap run completed.", "success")
    else:
        flash("Ettercap exited with warnings/errors. Review the output below.", "warning")

    return render_template(
        "results.html",
        result=res,
        parsed_ettercap=summary,
        title=title,
        active_page="ettercap",
    )


@app.route("/api/ettercap/sniff/status")
def ettercap_sniff_status():
    return jsonify(background_sniffer.status())


@app.route("/api/ettercap/sniff/start", methods=["POST"])
def ettercap_sniff_start():
    payload = request.get_json(silent=True) or {}
    token = payload.get("engagement_token")
    if not require_active_session(token or ""):
        return jsonify({"running": False, "error": "Invalid or missing engagement token."}), 400

    interface = (payload.get("interface") or "").strip()
    if not interface:
        return jsonify({"running": False, "error": "Interface is required."}), 400

    user = (payload.get("user") or "operator").strip() or "operator"
    quiet = _coerce_bool(payload.get("quiet"), default=True)
    text_mode = _coerce_bool(payload.get("text_mode"), default=True)
    plugin = (payload.get("plugin") or "").strip() or None
    filter_script = (payload.get("filter_script") or "").strip() or None
    log_file = (payload.get("log_file") or "").strip() or None
    target_a = (payload.get("target_a") or "").strip() or None
    target_b = (payload.get("target_b") or "").strip() or None
    extra_args_raw = (payload.get("extra_args") or "").strip()

    extra_args = None
    if extra_args_raw:
        try:
            extra_args = shlex.split(extra_args_raw)
        except ValueError:
            return jsonify({"running": False, "error": "Unable to parse extra arguments."}), 400

    pcap_file_input = (payload.get("pcap_file") or "").strip() or None
    if pcap_file_input:
        pcap_file = resolve_pcap_output_path(user, pcap_file_input)
    else:
        pcap_file = resolve_pcap_output_path(user, None)

    try:
        result = background_sniffer.start(
            user=user,
            interface=interface,
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
    except RuntimeError as exc:
        return jsonify({"running": False, "error": str(exc)}), 400
    except ValueError as exc:
        return jsonify({"running": False, "error": str(exc)}), 400

    return jsonify(result)


@app.route("/api/ettercap/sniff/stop", methods=["POST"])
def ettercap_sniff_stop():
    payload = request.get_json(silent=True) or {}
    token = payload.get("engagement_token")
    if not require_active_session(token or ""):
        return jsonify({"running": False, "error": "Invalid or missing engagement token."}), 400

    result = background_sniffer.stop()
    result.setdefault("running", False)
    return jsonify(result)


@app.route("/run_non_intrusive", methods=["POST"])
def run_non_intrusive():
    tool = (request.form.get("tool") or "").strip()

    # If dropdown is "custom", take custom text; else use dropdown value
    selected = (request.form.get("target") or "").strip()
    if selected == "__custom__":
        target_input = (request.form.get("target_custom") or ".").strip()
    else:
        target_input = selected or "."

    user = (request.form.get("user") or "local-user").strip() or "local-user"

    # Normalize the target path (supports ".", relative paths, ~, etc.)
    target_path = Path(target_input).expanduser()
    if not target_path.is_absolute():
        target_path = (BASE_DIR / target_path).resolve()

    if not target_path.exists():
        flash(f"Target path does not exist: {target_path}", "danger")
        return redirect(url_for("index"))

    # Non-intrusive tools
    if tool == "bandit":
        # Optional UI fields
        bandit_exclude = (request.form.get("bandit_exclude") or "").strip()
        bandit_skip = (request.form.get("bandit_skip") or "").strip()

        args = ["-r", str(target_path), "-f", "json"]

        if bandit_exclude:
            ex_list = [p.strip() for p in bandit_exclude.split(",") if p.strip()]
            if ex_list:
                norm = []
                for p in ex_list:
                    pp = Path(p).expanduser()
                    if not pp.is_absolute():
                        pp = (BASE_DIR / pp).resolve()
                    norm.append(str(pp))
                args += ["-x", ",".join(norm)]

        if bandit_skip:
            skip_list = [s.strip() for s in bandit_skip.split(",") if s.strip()]
            if skip_list:
                args += ["-s", ",".join(skip_list)]

        res = run_tool(
            user=user,
            tool="bandit",
            target=str(target_path),
            args=args,
        )
        parsed = parse_bandit_json(res.get("stdout", ""))
        title = "Bandit Result"
        if res.get("returncode", 0) == 1 and parsed["findings"]:
            flash(f"Bandit found {len(parsed['findings'])} finding(s).", "warning")
        elif res.get("returncode", 0) != 0:
            flash("Bandit exited with an error. See raw output below.", "danger")
        else:
            flash("Bandit completed with no findings.", "success")
        return render_template(
            "results.html",
            result=res,
            parsed_bandit=parsed,
            title=title,
            active_page="home",
        )

    if tool == "pip-audit":
        res = run_tool(
            user=user,
            tool="pip-audit",
            target=str(target_path),
            args=["--format", "json"],
        )
        if res.get("returncode", 0) == 0:
            flash("Dependency audit completed.", "success")
        else:
            flash("Dependency audit returned a non-zero status. See details below.", "warning")
        return render_template(
            "results.html",
            result=res,
            title="Dependency Audit",
            active_page="home",
        )

    flash("Unknown non-intrusive tool requested", "danger")
    return redirect(url_for("index"))


@app.route("/run_appsec_suite", methods=["POST"])
def run_appsec_suite():
    tool = (request.form.get("tool") or "").strip()
    target = (request.form.get("target") or "").strip()
    user = (request.form.get("user") or "operator").strip() or "operator"
    token = request.form.get("engagement_token")

    if not target:
        flash("Target is required.", "danger")
        return redirect(url_for("index"))

    active_required = tool in {"zap-baseline", "zap-api", "zap-full", "trivy", "grype", "checkov"}
    if active_required and not require_active_session(token or ""):
        flash("Engagement token required for active or network-facing scans.", "danger")
        return redirect(url_for("index"))

    if tool == "zap-baseline":
        res = zap_scan(user=user, target=target, mode="baseline")
        title = f"ZAP baseline: {target}"
    elif tool == "zap-api":
        api_def = (request.form.get("api_definition") or "").strip() or None
        res = zap_scan(user=user, target=target, mode="api", api_def=api_def)
        title = f"ZAP API: {target}"
    elif tool == "zap-full":
        policy = (request.form.get("zap_policy") or "").strip() or None
        ajax_spider = _coerce_bool(request.form.get("ajax_spider"))
        res = zap_scan(user=user, target=target, mode="full", policy=policy, ajax_spider=ajax_spider)
        title = f"ZAP full: {target}"
    elif tool == "gitleaks":
        res = gitleaks_scan(user=user, target=target)
        title = f"Gitleaks: {target}"
    elif tool == "trufflehog":
        res = trufflehog_scan(user=user, target=target)
        title = f"TruffleHog: {target}"
    elif tool == "trivy":
        res = trivy_scan(user=user, target=target)
        title = f"Trivy: {target}"
    elif tool == "grype":
        res = grype_scan(user=user, target=target)
        title = f"Grype: {target}"
    elif tool == "checkov":
        res = checkov_scan(user=user, target=target)
        title = f"Checkov: {target}"
    elif tool == "volatility":
        plugin = (request.form.get("vol_plugin") or "pslist").strip() or "pslist"
        res = volatility_inspect(user=user, target=target, plugin=plugin)
        title = f"Volatility ({plugin}): {target}"
    elif tool == "spiderfoot":
        raw_modules = request.form.get("spiderfoot_modules")
        modules = [m.strip() for m in (raw_modules or "").split(",") if m.strip()] or None
        res = spiderfoot_scan(user=user, target=target, modules=modules)
        title = f"SpiderFoot: {target}"
    else:
        flash("Unknown tool requested.", "danger")
        return redirect(url_for("index"))

    return render_template(
        "results.html",
        result=res,
        title=title,
        active_page="home",
    )


@app.route("/run_standard_suite", methods=["POST"])
def run_standard_suite():
    """Run the default active trio and persist artifacts for quick baselining."""

    token = request.form.get("engagement_token")
    if not require_active_session(token or ""):
        flash("Invalid or missing engagement token. Active scans denied.", "danger")
        return redirect(url_for("index"))

    target = (request.form.get("target") or "").strip()
    user = (request.form.get("user") or "operator").strip() or "operator"
    capture_traffic = _coerce_bool(request.form.get("capture_traffic"), default=True)
    interface = (request.form.get("capture_interface") or "").strip()

    if not target:
        flash("Target required for the standard sweep.", "danger")
        return redirect(url_for("index"))

    started = datetime.now(UTC)
    slug = _slugify_target(target)
    logs_dir = BASE_DIR / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    report_path = logs_dir / f"standard-suite-{started.strftime('%Y%m%d-%H%M%S')}-{slug}.txt"

    steps: list[dict[str, Any]] = []
    sniff_started = False
    sniff_summary: dict[str, Any] | None = None
    sniff_error: str | None = None
    pcap_file: str | None = None

    if capture_traffic:
        if not interface:
            flash("Interface required to capture packets. Capture skipped.", "warning")
        else:
            try:
                pcap_file = resolve_pcap_output_path(user, f"standard-suite-{slug}.pcap")
                sniff_resp = background_sniffer.start(
                    user=user,
                    interface=interface,
                    quiet=True,
                    text_mode=True,
                    pcap_file=pcap_file,
                )
                sniff_started = sniff_resp.get("running", False)
                sniff_summary = sniff_resp.get("summary")
            except Exception as exc:  # pragma: no cover - runtime safeguard
                sniff_error = str(exc)
                flash(f"Packet capture could not start: {exc}", "warning")

    def _append_step(name: str, run: dict[str, Any]) -> None:
        preview = (run.get("stdout") or "").splitlines()
        steps.append(
            {
                "name": name,
                "returncode": run.get("returncode"),
                "stdout": run.get("stdout") or "",
                "stderr": run.get("stderr") or "",
                "started_at": run.get("started_at"),
                "finished_at": run.get("finished_at"),
                "preview": "\n".join(preview[:8]),
            }
        )

    try:
        nmap_res = nmap_scan(user=user, target=target, profile="standard", extra_args=["-oN", "-"])
        _append_step("Nmap (standard)", nmap_res)

        nikto_res = nikto_scan(user=user, target_url=target)
        _append_step("Nikto", nikto_res)

        scapy_res = scapy_ping_scan(user=user, target=target, count=4, timeout=2.0)
        _append_step("Scapy ICMP", scapy_res)
    finally:
        if sniff_started:
            stop_result = background_sniffer.stop()
            if stop_result:
                sniff_summary = sniff_summary or {}
                sniff_summary["stopped"] = True
                sniff_summary["stop_message"] = stop_result.get("message")

    lines: list[str] = []
    lines.append("# Standard sweep report")
    lines.append(f"Target: {target}")
    lines.append(f"Operator: {user}")
    lines.append(f"Started: {started.isoformat()}")
    if pcap_file:
        lines.append(f"PCAP: {pcap_file}")
    if sniff_error:
        lines.append(f"Capture warning: {sniff_error}")
    lines.append("")

    for step in steps:
        lines.append(f"## {step['name']}")
        lines.append(f"Return code: {step['returncode']}")
        if step.get("started_at"):
            lines.append(f"Started: {step['started_at']}")
        if step.get("finished_at"):
            lines.append(f"Finished: {step['finished_at']}")
        lines.append("-- STDOUT --")
        lines.append(step.get("stdout") or "(empty)")
        if step.get("stderr"):
            lines.append("-- STDERR --")
            lines.append(step["stderr"])
        lines.append("")

    with report_path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    try:
        report_display = report_path.relative_to(BASE_DIR)
    except ValueError:
        report_display = report_path

    suite_result = {
        "target": target,
        "user": user,
        "report_path": str(report_display),
        "pcap_path": pcap_file,
        "started_at": started.isoformat(),
        "steps": steps,
        "sniff_summary": sniff_summary,
        "sniff_error": sniff_error,
    }

    flash("Standard sweep finished. Logs saved to disk.", "success")
    return render_template(
        "results.html",
        result={"steps": len(steps)},
        suite_result=suite_result,
        title=f"Standard sweep: {target}",
        active_page="home",
    )


@app.route("/run_active", methods=["POST"])
def run_active():
    token = request.form.get("engagement_token")
    if not require_active_session(token or ""):
        flash("Invalid or missing engagement token. Active scans denied.", "danger")
        return redirect(url_for("index"))

    tool = (request.form.get("tool") or "").strip()
    target = (request.form.get("target") or "").strip()
    user = (request.form.get("user") or "operator").strip() or "operator"
    profile = None
    extra_args_raw = ""
    if tool == "nmap":
        profile = (request.form.get("nmap_profile") or "").strip() or None
        extra_args_raw = (request.form.get("extra_args") or "").strip()

    if not target:
        flash("Target required for active scans.", "danger")
        return redirect(url_for("index"))

    # Split extra args (space-separated). Keep None if empty.
    extra_args_list = extra_args_raw.split() if extra_args_raw else None

    if tool == "nmap":
        if profile == "vuln-scan":
            flash("Warning: 'vuln-scan' uses NSE scripts and can be intrusive. Ensure authorization.", "warning")

        # Ensure we get XML on stdout for parsing unless user already provided -o options
        extra_args_list = extra_args_list or []
        if not any(a.startswith("-o") for a in extra_args_list):
            extra_args_list = extra_args_list + ["-oX", "-"]

        res = nmap_scan(user=user, target=target, profile=profile, extra_args=extra_args_list)

        # Parse Nmap XML into readable structure
        from cybercheck.utils.parsers import parse_nmap_xml
        parsed = parse_nmap_xml(res.get("stdout", "") or "")

        hosts_up = parsed.get("summary", {}).get("hosts_up")
        hosts_total = parsed.get("summary", {}).get("hosts_total")
        if hosts_up is not None and hosts_total is not None:
            if hosts_up > 0:
                flash(f"Nmap: {hosts_up}/{hosts_total} host(s) up.", "success")
            else:
                flash("Nmap completed: no hosts up.", "info")

        return render_template(
            "results.html",
            result=res,
            parsed_nmap=parsed,
            title=f"Nmap: {target}",
            active_page="home",
        )

    if tool == "nikto":
        res = nikto_scan(user=user, target_url=target)
        return render_template(
            "results.html",
            result=res,
            title=f"Nikto: {target}",
            active_page="home",
        )

    if tool == "scapy":
        try:
            scapy_count = int((request.form.get("scapy_count") or "").strip() or 4)
            scapy_timeout = float((request.form.get("scapy_timeout") or "").strip() or 2.0)
        except ValueError:
            flash("Invalid Scapy options provided.", "danger")
            return redirect(url_for("index"))

        if scapy_count <= 0 or scapy_timeout <= 0:
            flash("Scapy count and timeout must be positive values.", "danger")
            return redirect(url_for("index"))

        res = scapy_ping_scan(
            user=user,
            target=target,
            count=scapy_count,
            timeout=scapy_timeout,
        )

        report = res.get("report") or {}
        summary = report.get("summary") or {}

        if res.get("stderr"):
            flash("Scapy encountered an error. See details below.", "danger")
        elif summary.get("status") == "up":
            recv = summary.get("received", 0)
            flash(f"Scapy: host responded to {recv} ICMP probe(s).", "success")
        else:
            flash("Scapy completed: no responses received.", "info")

        return render_template(
            "results.html",
            result=res,
            parsed_scapy=report,
            title=f"Scapy ICMP: {target}",
            active_page="home",
        )

    flash("Unknown active tool.", "danger")
    return redirect(url_for("index"))


@app.route("/api/runs")
def api_runs():
    rows = fetch_last_runs(50)
    out = [dict(r) for r in rows]
    return jsonify(out)


@app.route("/api/compliance")
def api_compliance():
    report = build_control_report(50)
    return jsonify(report)


@app.route("/dashboard")
def dashboard():
    runs = fetch_last_runs(50)
    assets = fetch_asset_inventory()
    controls = fetch_control_mappings()
    findings = fetch_findings(12)
    totals = Counter((r["tool"] or "unknown").lower() for r in runs)

    durations: list[float] = []
    latest_finished: datetime | None = None
    timeline: list[dict] = []
    per_target: dict[tuple[str, str], dict] = {}

    for row in runs:
        tool = (row["tool"] or "unknown").lower()
        target = row["target"] or "—"
        finished = _parse_timestamp(row["finished_at"]) or _parse_timestamp(row["started_at"])
        started = _parse_timestamp(row["started_at"])

        if started and finished and finished >= started:
            durations.append((finished - started).total_seconds())

        if finished and (latest_finished is None or finished > latest_finished):
            latest_finished = finished

        returncode = row["returncode"]
        if returncode == 0:
            status_key, status_label, status_hint = "healthy", "Operational", "All checks passed"
        elif returncode is None:
            status_key, status_label, status_hint = "unknown", "Pending", "Awaiting execution"
        elif returncode > 0:
            status_key, status_label, status_hint = "attention", "Review findings", "Scanner reported findings"
        else:
            status_key, status_label, status_hint = "error", "Tool error", "Execution failed or timed out"

        record_key = (tool, target)
        previous = per_target.get(record_key)
        if not previous or (finished and finished > previous["ts"]):
            per_target[record_key] = {
                "tool": tool,
                "tool_display": tool.upper(),
                "target": target,
                "status_key": status_key,
                "status_label": status_label,
                "status_hint": status_hint,
                "returncode": returncode,
                "finished": finished,
                "finished_display": _format_timestamp(finished),
                "ts": finished or started,
                "operator": row["user"] or "—",
            }

        timeline.append(
            {
                "tool": tool,
                "tool_display": tool.upper(),
                "target": target,
                "operator": row["user"] or "—",
                "finished": finished,
                "finished_display": _format_timestamp(finished),
                "status_key": status_key,
                "status_hint": status_hint,
            }
        )

    avg_duration = sum(durations) / len(durations) if durations else 0.0
    tool_totals = [
        {"key": key, "label": key.upper(), "count": count}
        for key, count in sorted(totals.items(), key=lambda kv: kv[0])
    ]
    target_cards = sorted(
        per_target.values(),
        key=lambda item: item["ts"] or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    timeline = sorted(
        timeline,
        key=lambda item: item["finished"] or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )[:10]

    overview = {
        "total_runs": len(runs),
        "avg_duration": avg_duration,
        "last_finished": _format_timestamp(latest_finished),
    }

    coverage = {
        "assets": assets,
        "controls": controls,
        "uncovered_controls": [c for c in controls if (c["asset_total"] or 0) == 0],
        "open_findings": sum((row["open_findings"] or 0) for row in assets),
    }

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        overview=overview,
        tool_totals=tool_totals,
        target_cards=target_cards,
        timeline=timeline,
        coverage=coverage,
        findings=findings,
    )


@app.route("/monitor")
def monitor() -> str:
    network_monitor.ensure_running()
    return render_template(
        "monitor.html",
        active_page="monitor",
        window_seconds=network_monitor.window_seconds,
    )


@app.route("/api/network_snapshot")
def api_network_snapshot():
    network_monitor.ensure_running()
    return jsonify(network_monitor.snapshot())


@app.route("/network-map")
def network_map() -> str:
    network_monitor.ensure_running()
    return render_template(
        "network_map.html",
        active_page="network_map",
        window_seconds=network_monitor.window_seconds,
    )


@app.route("/api/network_topology")
def api_network_topology():
    network_monitor.ensure_running()
    snapshot = network_monitor.snapshot()
    topology = snapshot.get("topology", {"nodes": [], "links": []})
    topology["metadata"] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "uptime": snapshot.get("uptime"),
        "window_seconds": snapshot.get("window", {}).get("seconds"),
        "packets_in_window": snapshot.get("window", {}).get("packets"),
    }
    return jsonify(topology)

@app.route("/api/network_interfaces")
def api_network_interfaces():
    """
    Return a list of available capture interfaces and which one is active.
    """
    try:
        from scapy.all import get_if_addr, get_if_list  # type: ignore

        interfaces = []
        for iface in get_if_list():
            try:
                ip_addr = get_if_addr(iface)
            except Exception:
                ip_addr = None

            interfaces.append({
                "name": iface,
                "address": ip_addr if ip_addr and ip_addr != "0.0.0.0" else None,
            })
    except Exception:
        interfaces = []

    return jsonify({
        "interfaces": interfaces,
        "active": network_monitor.interface,
    })


@app.route("/api/network_interface", methods=["POST"])
def api_set_network_interface():
    """
    Switch the network monitor to a different interface.
    """
    payload = request.get_json(silent=True) or {}
    iface = (payload.get("interface") or "").strip() or None

    # iface = None => default Scapy interface
    network_monitor.set_interface(iface)

    return jsonify({
        "interface": network_monitor.interface,
    })


# ---- Alerts, scheduling, and regression helpers ----
@app.route("/api/alerts", methods=["GET", "POST"])
def api_alerts():
    token = request.args.get("token")
    if request.method == "POST":
        if not require_active_session(token or ""):
            return {"error": "forbidden"}, 403
        payload = request.get_json(force=True, silent=True) or {}
        alert_id = alert_pipeline.emit(
            source=payload.get("source", "manual"),
            severity=payload.get("severity", "info"),
            message=payload.get("message", ""),
            metadata=payload.get("metadata"),
        )
        return {"id": alert_id, "status": "queued"}
    alerts = alert_pipeline.list_recent()
    return jsonify([dict(a) for a in alerts])


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_alert_ack(alert_id: int):
    user = current_user()
    if not user:
        return {"error": "forbidden"}, 403
    alert_pipeline.acknowledge(alert_id, user["username"])
    return {"status": "acknowledged"}


@app.route("/api/alerts/<int:alert_id>/suppress", methods=["POST"])
def api_alert_suppress(alert_id: int):
    user = current_user()
    if not user:
        return {"error": "forbidden"}, 403
    minutes = int((request.get_json(force=True, silent=True) or {}).get("minutes", 30))
    alert_pipeline.suppress(alert_id, minutes=minutes)
    return {"status": "suppressed"}


@app.route("/api/schedules/reload", methods=["POST"])
def api_reload_schedules():
    token = request.args.get("token")
    if not require_active_session(token or ""):
        return {"error": "forbidden"}, 403
    scan_scheduler.start()
    scan_scheduler.load_jobs()
    return {"status": "reloaded"}


@app.route("/api/firewall/run", methods=["POST"])
@require_role("analyst")
def api_firewall_run():
    user = current_user()
    payload = request.get_json(force=True, silent=True) or {}
    target = payload.get("target")
    if not target:
        return {"error": "target is required"}, 400
    expectations = payload.get("expectations", [])
    results = run_firewall_matrix(user["username"], target, expectations)
    return {"target": target, "results": results}


@app.route("/api/firewall/pentest", methods=["POST"])
@require_role("analyst")
def api_firewall_pentest():
    user = current_user()
    payload = request.get_json(force=True, silent=True) or {}
    target = payload.get("target")
    if not target:
        return {"error": "target is required"}, 400
    report = run_firewall_pentest(user["username"], target)
    return {"target": target, "report": report}


@app.route("/api/detections/register", methods=["POST"])
@require_role("analyst")
def api_detections_register():
    payload = request.get_json(force=True, silent=True) or {}
    register_validation(payload.get("name", ""), payload.get("scenario", ""), payload.get("expected_signal", ""))
    return {"status": "registered"}


@app.route("/api/detections/replay", methods=["POST"])
@require_role("analyst")
def api_detections_replay():
    payload = request.get_json(force=True, silent=True) or {}
    analysis = replay_pcap(payload.get("pcap_path", ""))
    return {"analysis": analysis}


@app.route("/api/detections/<int:validation_id>/result", methods=["POST"])
@require_role("analyst")
def api_detections_result(validation_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    record_result(validation_id, payload.get("result", "unknown"), payload.get("notes"))
    return {"status": "recorded"}


if __name__ == "__main__":
    # Debug only when explicitly enabled; never hardcode True
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
