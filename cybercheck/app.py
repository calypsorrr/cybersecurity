from __future__ import annotations

from collections import Counter, OrderedDict
import secrets
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from tempfile import NamedTemporaryFile

from cybercheck.config import SECRET_KEY, NMAP_PROFILES
from cybercheck.utils.auth import require_active_session
from cybercheck.scanners import nmap_scan, nikto_scan, scapy_ping_scan
from cybercheck.scanners import run_ettercap
from cybercheck.scanners.runner import run_tool
from cybercheck.models.db import fetch_last_runs
from cybercheck.utils.parsers import parse_bandit_json  # Bandit -> readable report
from cybercheck.utils.monitor import network_monitor
from cybercheck.utils.capture import analyze_pcap_file
from cybercheck.utils.background_sniffer import background_sniffer
from cybercheck.utils.pcap_paths import resolve_pcap_output_path

try:
    from datetime import UTC
except ImportError:  # pragma: no cover - Python <3.11 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc

BASE_DIR = Path(__file__).resolve().parent

WIRESHARK_CACHE_LIMIT = 6
WIRESHARK_RUN_CACHE: OrderedDict[str, Dict[str, Any]] = OrderedDict()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return False
    return text in {"1", "true", "yes", "on"}


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
    presets = list_project_targets()
    active_tools = {"nmap", "nikto", "scapy"}
    active_runs = [r for r in runs if (r["tool"] or "").lower() in active_tools]
    last_active = _parse_timestamp(active_runs[0]["finished_at"]) if active_runs else None
    metrics = {
        "total_runs": len(runs),
        "active_runs": len(active_runs),
        "last_active_finished": _format_timestamp(last_active),
    }
    return render_template(
        "index.html",
        runs=runs,
        nmap_profiles=list(NMAP_PROFILES.keys()),
        scan_presets=presets,
        metrics=metrics,
        active_page="home",
    )


@app.route("/scan-help")
def scan_help():
    scan_guides = [
        {
            "name": "Nmap",
            "tagline": "Network discovery, service fingerprinting & basic vuln probing",
            "summary": "Use Nmap when you need to map hosts, enumerate ports/services, or verify exposure before and after changes.",
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
        },
        {
            "name": "Nikto",
            "tagline": "Web server misconfiguration & vulnerability sweeps",
            "summary": "Run Nikto when validating HTTP/S attack surface: outdated servers, dangerous files, SSL issues, and known CVEs.",
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
        },
        {
            "name": "Scapy",
            "tagline": "Packet crafting for validation, troubleshooting & custom probes",
            "summary": "Use Scapy when you need programmable packets: crafting probes, validating firewall rules, or building custom detections.",
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
            "task": "Test firewall rules or reproduce IDS alerts with crafted packets",
            "recommended": "Scapy (sr/srp/sendp) with custom layers",
            "why": "Lets you build packets by hand and observe responses in real time.",
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
    ]

    return render_template(
        "scan_help.html",
        active_page="scan_help",
        guides=scan_guides,
        decision_matrix=decision_matrix,
        nmap_profiles=NMAP_PROFILES,
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
    )


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


@app.route("/dashboard")
def dashboard():
    runs = fetch_last_runs(50)
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

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        overview=overview,
        tool_totals=tool_totals,
        target_cards=target_cards,
        timeline=timeline,
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


if __name__ == "__main__":
    # Debug only when explicitly enabled; never hardcode True
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
