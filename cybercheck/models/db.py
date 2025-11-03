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
        """
    )
    conn.commit()
    conn.close()


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


# initialize DB on import
init_db()
