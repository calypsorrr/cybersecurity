import json
from models.db import fetch_last_runs




def generate_json_report(limit=100):
    rows = fetch_last_runs(limit)
    out = [dict(r) for r in rows]
    return json.dumps({"generated_at": __import__('datetime').datetime.utcnow().isoformat(), "runs": out}, indent=2)