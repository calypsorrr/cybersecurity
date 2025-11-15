import json
import sys
from pathlib import Path
from unittest import TestCase

PROJECT_PARENT = Path(__file__).resolve().parents[2]
if str(PROJECT_PARENT) not in sys.path:
    sys.path.insert(0, str(PROJECT_PARENT))

from cybercheck.utils.parsers import parse_bandit_json


class ParseBanditJsonTests(TestCase):
    def test_invalid_json_returns_stub(self):
        result = parse_bandit_json("not-json")

        self.assertEqual(result["summary"]["errors"], ["Invalid Bandit JSON"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["raw"], "not-json")

    def test_collects_totals_and_errors(self):
        payload = {
            "errors": [{"filename": "a.py", "reason": "bad"}],
            "metrics": {"_totals": {"loc": 10}},
            "results": [
                {
                    "filename": "b.py",
                    "line_number": 42,
                    "code": "print('x')",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Danger",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_cwe": {"id": 798},
                    "more_info": "https://example.test",
                }
            ],
        }

        result = parse_bandit_json(json.dumps(payload))

        self.assertEqual(result["summary"]["totals"], {"loc": 10})
        self.assertEqual(result["summary"]["errors"], ["a.py: bad"])
        self.assertEqual(result["summary"]["severity_counts"], {"HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNDEFINED": 0})
        finding = result["findings"][0]
        self.assertEqual(finding["file"], "b.py")
        self.assertEqual(finding["cwe"], 798)
