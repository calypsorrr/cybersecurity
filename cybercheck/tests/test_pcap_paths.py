import sys
import tempfile
from pathlib import Path
from unittest import TestCase, mock

PROJECT_PARENT = Path(__file__).resolve().parents[2]
if str(PROJECT_PARENT) not in sys.path:
    sys.path.insert(0, str(PROJECT_PARENT))

from cybercheck.utils import pcap_paths


class ResolvePcapOutputPathTests(TestCase):
    def test_default_path_is_under_capture_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with mock.patch.object(pcap_paths, "_DEFAULT_PCAP_DIR", base):
                result = Path(pcap_paths.resolve_pcap_output_path("analyst"))

        self.assertTrue(result.is_absolute())
        self.assertTrue(str(result).endswith(".pcap"))
        self.assertEqual(result.parent, base)

    def test_rejects_directory_traversal_attempts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with mock.patch.object(pcap_paths, "_DEFAULT_PCAP_DIR", base):
                with self.assertRaises(ValueError):
                    pcap_paths.resolve_pcap_output_path("analyst", "../escape.pcap")

    def test_allows_absolute_paths_inside_capture_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            nested = base / "custom" / "trace.pcap"
            with mock.patch.object(pcap_paths, "_DEFAULT_PCAP_DIR", base):
                result = Path(pcap_paths.resolve_pcap_output_path("analyst", str(nested)))

        self.assertEqual(result, nested.resolve())
