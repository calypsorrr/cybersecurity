from pathlib import Path
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from cybercheck.config import SECRET_KEY, NMAP_PROFILES
from cybercheck.utils.auth import require_active_session
from cybercheck.scanners import nmap_scan, nikto_scan, scapy_ping_scan
from cybercheck.scanners.runner import run_tool
from cybercheck.models.db import fetch_last_runs
from cybercheck.utils.parsers import parse_bandit_json  # Bandit -> readable report

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = SECRET_KEY


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


@app.route("/")
def index():
    runs = fetch_last_runs(20)
    presets = list_project_targets()
    return render_template(
        "index.html",
        runs=runs,
        nmap_profiles=list(NMAP_PROFILES.keys()),
        scan_presets=presets,
    )


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
        return render_template("results.html", result=res, parsed_bandit=parsed, title=title)

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
        return render_template("results.html", result=res, title="Dependency Audit")

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

        return render_template("results.html", result=res, parsed_nmap=parsed, title=f"Nmap: {target}")

    if tool == "nikto":
        res = nikto_scan(user=user, target_url=target)
        return render_template("results.html", result=res, title=f"Nikto: {target}")

    if tool == "scapy":
        try:
            scapy_count = int((request.form.get("scapy_count") or "").strip() or 4)
            scapy_timeout = float((request.form.get("scapy_timeout") or "").strip() or 2.0)
            scapy_interval = float((request.form.get("scapy_interval") or "").strip() or 1.0)
            scapy_payload_size = int((request.form.get("scapy_payload_size") or "").strip() or 32)
        except ValueError:
            flash("Invalid Scapy options provided.", "danger")
            return redirect(url_for("index"))

        if scapy_count <= 0 or scapy_timeout <= 0 or scapy_interval < 0 or scapy_payload_size < 0:
            flash("Scapy count/timeout must be positive and interval/payload size cannot be negative.", "danger")
            return redirect(url_for("index"))

        if scapy_payload_size > 65500:
            flash("Scapy payload size capped at 65500 bytes for IPv4.", "danger")
            return redirect(url_for("index"))

        payload_raw = request.form.get("scapy_payload_data")
        payload_data = payload_raw if payload_raw else None
        if payload_data is not None and len(payload_data) > 4096:
            flash("Custom payload limited to 4096 characters.", "danger")
            return redirect(url_for("index"))

        def _parse_optional_int(field_name: str):
            raw = (request.form.get(field_name) or "").strip()
            if not raw:
                return None
            try:
                return int(raw, 0)
            except ValueError:
                raise ValueError(f"Invalid integer for {field_name}")

        try:
            icmp_type = _parse_optional_int("scapy_icmp_type")
            icmp_code = _parse_optional_int("scapy_icmp_code")
            icmp_id = _parse_optional_int("scapy_icmp_id")
        except ValueError:
            flash("ICMP type/code/id must be integers (decimal or 0x-prefixed hex).", "danger")
            return redirect(url_for("index"))

        res = scapy_ping_scan(
            user=user,
            target=target,
            count=scapy_count,
            timeout=scapy_timeout,
            interval=scapy_interval,
            payload_size=scapy_payload_size,
            payload_data=payload_data,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_id=icmp_id,
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
        )

    flash("Unknown active tool.", "danger")
    return redirect(url_for("index"))


@app.route("/api/runs")
def api_runs():
    rows = fetch_last_runs(50)
    out = [dict(r) for r in rows]
    return jsonify(out)


if __name__ == "__main__":
    # Debug only when explicitly enabled; never hardcode True
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
