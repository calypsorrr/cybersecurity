import sys
from pathlib import Path
from unittest import TestCase

PROJECT_PARENT = Path(__file__).resolve().parents[2]
if str(PROJECT_PARENT) not in sys.path:
    sys.path.insert(0, str(PROJECT_PARENT))

from cybercheck.utils.capture import extract_interesting_packets
from cybercheck.utils.wireshark_filters import SENSITIVE_PROTOCOL_FILTERS


class ExtractInterestingPacketsTests(TestCase):
    def test_flags_sensitive_protocol_hosts_and_ports(self):
        report = {
            "talkers": [{"label": "10.0.0.5", "count": 20}],
            "targets": [{"label": "10.0.0.10", "count": 15}],
            "all_samples": [
                {
                    "timestamp": "2024-01-01T00:00:01",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.10",
                    "proto": "DNS",
                    "length": 60,
                    "info": "DNS query",
                    "src_port": 51500,
                    "dst_port": 53,
                },
                {
                    "timestamp": "2024-01-01T00:00:02",
                    "src": "10.0.0.30",
                    "dst": "10.0.0.40",
                    "proto": "TCP",
                    "length": 60,
                    "info": "noise",
                    "src_port": 1234,
                    "dst_port": 4321,
                },
            ],
        }

        flagged = extract_interesting_packets(report)

        self.assertEqual(len(flagged), 1)
        highlights = flagged[0]["highlights"]
        self.assertIn(SENSITIVE_PROTOCOL_FILTERS["DNS"][1], highlights)
        self.assertTrue(any("busiest hosts" in entry for entry in highlights))
        self.assertTrue(any("port 53" in entry for entry in highlights))

    def test_returns_empty_list_when_no_samples(self):
        self.assertEqual(extract_interesting_packets(None), [])
        self.assertEqual(extract_interesting_packets({"all_samples": []}), [])
