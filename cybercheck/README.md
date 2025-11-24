# CyberCheck

CyberCheck is a Flask-based security operations dashboard that orchestrates reconnaissance, vulnerability scanning, OSINT, and packet analysis from a single web console. It wraps common CLI tools (Nmap, Nikto, SpiderFoot, ZAP, gitleaks, etc.), records each run in SQLite for auditing, and visualizes findings through reusable templates and JSON APIs.

## Getting started

1. **Install dependencies**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Set environment variables (optional)**
   - `SECRET_KEY`: Flask session secret (defaults to `dev-secret`).
   - `DATABASE`: Path to the SQLite database (defaults to `logs/cybercheck.db`).
   - `HOST`/`PORT`: Server bind address and port (defaults to `127.0.0.1:5000`).
   - `ENGAGEMENT_TOKEN`: Optional token used to protect sensitive routes.
   - `VIRUSTOTAL_API_KEY`: Optional key to enable hash reputation checks via VirusTotal.
3. **Initialize the database**
   ```bash
   python - <<'PY'
   from cybercheck.models.db import init_db
   init_db()
   PY
   ```
4. **Run the app**
   ```bash
   FLASK_DEBUG=1 python app.py
   ```
   Navigate to `http://127.0.0.1:5000` to access the dashboard.

### .env support

The application automatically loads environment variables from a `.env` file placed in the project root. To enable VirusTotal
hash reputation lookups, create a `.env` file alongside `config.py` with:

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```

Restart the application after updating the `.env` file so the new settings are picked up.

### Where the recent backend changes live

- **Session authentication and roles**: JSON endpoints for bootstrapping an admin, logging in, and logging out are under `/auth/*` in `app.py`. They use helpers in `utils/auth.py` and the `users` table in `models/db.py` to bind actions to verified identities while still supporting the legacy `ENGAGEMENT_TOKEN` for sensitive routes.
- **Alerting and suppression**: REST APIs at `/api/alerts` and `/api/alerts/<id>/ack|suppress` surface the alert pipeline defined in `utils/alerts.py` so alerts can be emitted, acknowledged, or temporarily muted.
- **Scheduling**: `/api/schedules/reload` reloads cron-based recurring scan jobs using the `scan_scheduler` helper in `utils/scheduler.py`, with APScheduler used when available and a safe no-op fallback otherwise.
- **Firewall regression & detection validation**: Analyst-only APIs at `/api/firewall/run` and `/api/detections/*` call helpers in `utils/firewall_regression.py` and `utils/detection_validation.py` to exercise allow/deny matrices, replay PCAPs, and record expected detection outcomes.

These additions extend the backend and API surface; the HTML templates have not yet been updated with new navigation or forms, so you will interact with them via HTTP requests or your own frontend wiring.

## Code flow (high level)

- **HTTP layer**: `app.py` defines Flask routes that validate user input, call scanning helpers, and render Jinja templates.
- **Execution layer**: `scanners/runner.py` wraps subprocess execution for whitelisted tools, capturing stdout/stderr and timing data.
- **Persistence layer**: `models/db.py` initializes and queries the SQLite database to store run history, assets, controls, and findings.
- **Utilities**: `utils/` contains parsing, monitoring, capture, and inspection helpers that surface structured data back to the views.

A typical scan request flows as:
1. User submits a target through the UI (route in `app.py`).
2. The route normalizes arguments and invokes `run_tool` to execute the CLI scanner.
3. `run_tool` writes a run record via `models.db.log_run` while returning stdout/stderr to the caller.
4. The route renders results or exposes them via `/api/...` endpoints, pulling historical context from the database.

## Directory overview

```
cybercheck/
├─ app.py             # Flask application, routes, and page composition
├─ config.py          # Environment configuration and Nmap profile defaults
├─ models/            # SQLite helpers and seed data
├─ scanners/          # Wrappers for CLI tools and scanning profiles
├─ utils/             # Parsers, monitoring, pcap handling, and background jobs
├─ templates/         # Jinja templates for HTML views
├─ static/            # Frontend assets (CSS/JS/images)
└─ tests/             # Test coverage for core utilities
```

## 3D structure (layered view)

```
          [ Frontend UX ]
          /  HTML + JS  \
        /----------------\
       /    Flask Views    \   <— Presentation plane (routes + templates)
      /----------------------\
     /  Orchestration Layer   \  <— Coordination plane (argument parsing, validation)
    /--------------------------\
   /  Execution & Telemetry     \ <— Engine plane (CLI tools, DB logging)
  /------------------------------\
 [ Scanners ]  [ Utils ]  [ DB ]
```

- The **presentation plane** lives in `app.py` and `templates/`.
- The **coordination plane** is split between `app.py` helpers and `utils/` modules.
- The **engine plane** runs CLI tools via `scanners/runner.py` and persists context through `models/db.py`.

## Operational tips

- Keep `ALLOWED_TOOLS` in `config.py` aligned with what is installed on the host.
- Long-running scans can use route parameters to adjust timeouts; everything still funnels through `run_tool` for consistent logging.
- The network monitor in `utils/monitor.py` degrades gracefully when packet capture permissions are unavailable, so the dashboard remains responsive in restricted environments.
