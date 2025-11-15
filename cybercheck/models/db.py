import sqlite3
from datetime import datetime
from pathlib import Path
from cybercheck.config import DATABASE

# Ensure DB directory exists
Path(DATABASE).parent.mkdir(parents=True, exist_ok=True)

# UTC import fallback
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            tool TEXT,
            target TEXT,
            args TEXT,
            started_at TEXT,
            finished_at TEXT,
            returncode INTEGER,
            stdout TEXT,
            stderr TEXT
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            owner TEXT,
            business_unit TEXT,
            criticality TEXT,
            scope TEXT,
            attack_surface TEXT,
            sla_days INTEGER DEFAULT 30,
            tags TEXT
        );

        CREATE TABLE IF NOT EXISTS controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            framework TEXT,
            reference TEXT,
            tactic TEXT,
            description TEXT,
            frequency TEXT
        );

        CREATE TABLE IF NOT EXISTS asset_controls (
            asset_id INTEGER NOT NULL,
            control_id INTEGER NOT NULL,
            PRIMARY KEY (asset_id, control_id),
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY(control_id) REFERENCES controls(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            control_id INTEGER,
            title TEXT NOT NULL,
            severity TEXT,
            status TEXT,
            opened_at TEXT,
            updated_at TEXT,
            ticket TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL,
            FOREIGN KEY(control_id) REFERENCES controls(id) ON DELETE SET NULL
        );
        """
    )
    conn.commit()
    seed_reference_data(conn)
    conn.close()


def seed_reference_data(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    if cur.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0:
        cur.executemany(
            """
            INSERT INTO assets (name, category, owner, business_unit, criticality, scope, attack_surface, sla_days, tags)
            VALUES (:name, :category, :owner, :business_unit, :criticality, :scope, :attack_surface, :sla_days, :tags)
            """,
            [
                {
                    "name": "Customer Portal",
                    "category": "Web application",
                    "owner": "AppSec",
                    "business_unit": "Digital",
                    "criticality": "Critical",
                    "scope": "prod.apps.internal",
                    "attack_surface": "443/tcp, S3 assets, OAuth callbacks",
                    "sla_days": 7,
                    "tags": "internet-facing, pci",
                },
                {
                    "name": "Corporate VPN",
                    "category": "Network perimeter",
                    "owner": "Network Security",
                    "business_unit": "Infrastructure",
                    "criticality": "High",
                    "scope": "vpn.example.com/24",
                    "attack_surface": "UDP 500/4500, TLS gateway",
                    "sla_days": 14,
                    "tags": "remote-access, high-privilege",
                },
                {
                    "name": "Internal API Gateway",
                    "category": "Platform",
                    "owner": "Platform Engineering",
                    "business_unit": "Core Services",
                    "criticality": "High",
                    "scope": "10.20.0.0/22",
                    "attack_surface": "mTLS ingress, service mesh",
                    "sla_days": 30,
                    "tags": "east-west, microservices",
                },
            ],
        )

    if cur.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 0:
        cur.executemany(
            """
            INSERT INTO controls (name, framework, reference, tactic, description, frequency)
            VALUES (:name, :framework, :reference, :tactic, :description, :frequency)
            """,
            [
                {
                    "name": "Service Exposure Sweep",
                    "framework": "NIST CSF",
                    "reference": "DE.CM-7",
                    "tactic": "Reconnaissance",
                    "description": "Baseline internet exposure and discover newly opened services.",
                    "frequency": "Weekly",
                },
                {
                    "name": "Web App Misconfiguration",
                    "framework": "OWASP ASVS",
                    "reference": "V14",
                    "tactic": "Initial Access",
                    "description": "Check TLS posture, dangerous files, default creds and verbose headers.",
                    "frequency": "Per release",
                },
                {
                    "name": "Dependency Hygiene",
                    "framework": "NIST SSDF",
                    "reference": "PW.6",
                    "tactic": "Persistence",
                    "description": "Identify outdated or vulnerable packages in the build chain.",
                    "frequency": "Nightly",
                },
                {
                    "name": "Lateral Movement Detection",
                    "framework": "MITRE ATT&CK",
                    "reference": "TA0008",
                    "tactic": "Lateral Movement",
                    "description": "Detect anomalous ARP/DHCP/ICMP pivots inside trusted networks.",
                    "frequency": "Monthly",
                },
            ],
        )

    # Map controls to assets when no mappings exist
    if cur.execute("SELECT COUNT(*) FROM asset_controls").fetchone()[0] == 0:
        assets = {
            row["name"]: row["id"]
            for row in cur.execute("SELECT id, name FROM assets")
        }
        controls = {
            row["name"]: row["id"]
            for row in cur.execute("SELECT id, name FROM controls")
        }
        mappings = [
            (assets.get("Customer Portal"), controls.get("Service Exposure Sweep")),
            (assets.get("Customer Portal"), controls.get("Web App Misconfiguration")),
            (assets.get("Customer Portal"), controls.get("Dependency Hygiene")),
            (assets.get("Corporate VPN"), controls.get("Service Exposure Sweep")),
            (assets.get("Corporate VPN"), controls.get("Lateral Movement Detection")),
            (assets.get("Internal API Gateway"), controls.get("Dependency Hygiene")),
            (assets.get("Internal API Gateway"), controls.get("Lateral Movement Detection")),
        ]
        cur.executemany(
            "INSERT OR IGNORE INTO asset_controls (asset_id, control_id) VALUES (?, ?)",
            [(a, c) for a, c in mappings if a and c],
        )

    if cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0:
        assets = {
            row["name"]: row["id"]
            for row in cur.execute("SELECT id, name FROM assets")
        }
        controls = {
            row["name"]: row["id"]
            for row in cur.execute("SELECT id, name FROM controls")
        }
        now = datetime.now(UTC).isoformat()
        cur.executemany(
            """
            INSERT INTO findings (asset_id, control_id, title, severity, status, opened_at, updated_at, ticket)
            VALUES (:asset_id, :control_id, :title, :severity, :status, :opened_at, :updated_at, :ticket)
            """,
            [
                {
                    "asset_id": assets.get("Customer Portal"),
                    "control_id": controls.get("Web App Misconfiguration"),
                    "title": "TLS uses deprecated ciphers on legacy edge node",
                    "severity": "High",
                    "status": "Open",
                    "opened_at": now,
                    "updated_at": now,
                    "ticket": "JIRA-4021",
                },
                {
                    "asset_id": assets.get("Corporate VPN"),
                    "control_id": controls.get("Service Exposure Sweep"),
                    "title": "Exposed management interface reachable from guest Wi-Fi",
                    "severity": "Critical",
                    "status": "In progress",
                    "opened_at": now,
                    "updated_at": now,
                    "ticket": "SOC-1187",
                },
                {
                    "asset_id": assets.get("Internal API Gateway"),
                    "control_id": controls.get("Dependency Hygiene"),
                    "title": "Outdated JWT library across mesh sidecars",
                    "severity": "Medium",
                    "status": "Verified",
                    "opened_at": now,
                    "updated_at": now,
                    "ticket": "PLAT-932",
                },
            ],
        )

    conn.commit()


def log_run(
    user: str,
    tool: str,
    target: str,
    args: str,
    started_at: str,
    finished_at: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO runs (
                user, tool, target, args, started_at, finished_at,
                returncode, stdout, stderr
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user, tool, target, args, started_at, finished_at, returncode, stdout, stderr),
        )
        conn.commit()
    except Exception as e:
        # do not crash the app if logging fails
        print(f"[DB] Logging error: {e}")
    finally:
        if conn:
            conn.close()


def fetch_last_runs(limit: int = 25):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_asset_inventory():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            a.id,
            a.name,
            a.category,
            a.owner,
            a.business_unit,
            a.criticality,
            a.scope,
            a.attack_surface,
            a.sla_days,
            a.tags,
            COUNT(DISTINCT ac.control_id) AS control_total,
            GROUP_CONCAT(DISTINCT c.tactic) AS tactics,
            SUM(CASE WHEN f.status IN ('Open', 'In progress') THEN 1 ELSE 0 END) AS open_findings,
            SUM(CASE WHEN f.status = 'Verified' THEN 1 ELSE 0 END) AS verified_findings
        FROM assets a
        LEFT JOIN asset_controls ac ON a.id = ac.asset_id
        LEFT JOIN controls c ON ac.control_id = c.id
        LEFT JOIN findings f ON f.asset_id = a.id
        GROUP BY a.id
        ORDER BY CASE a.criticality WHEN 'Critical' THEN 3 WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END DESC, a.name
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_control_mappings():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            c.id,
            c.name,
            c.framework,
            c.reference,
            c.tactic,
            c.description,
            c.frequency,
            COUNT(DISTINCT ac.asset_id) AS asset_total,
            GROUP_CONCAT(DISTINCT a.name) AS assets
        FROM controls c
        LEFT JOIN asset_controls ac ON c.id = ac.control_id
        LEFT JOIN assets a ON a.id = ac.asset_id
        GROUP BY c.id
        ORDER BY c.name
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_findings(limit: int = 15):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            f.*, a.name AS asset_name, c.name AS control_name
        FROM findings f
        LEFT JOIN assets a ON a.id = f.asset_id
        LEFT JOIN controls c ON c.id = f.control_id
        ORDER BY datetime(f.opened_at) DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# initialize DB on import
init_db()
