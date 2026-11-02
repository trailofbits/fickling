import pickle
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from fickling.analysis import Severity, is_likely_safe


class TestIsLikelySafe(TestCase):
    def test_is_likely_safe_evaluates_all_stacked_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stacked.pkl"
            path.write_bytes(pickle.dumps({"label": 1}) + pickle.dumps({"label": 2}))
            verdicts = [
                SimpleNamespace(severity=Severity.LIKELY_SAFE),
                SimpleNamespace(severity=Severity.LIKELY_UNSAFE),
            ]
            with patch("fickling.analysis.check_safety", side_effect=verdicts) as scan:
                self.assertFalse(is_likely_safe(str(path)))
                self.assertEqual(scan.call_count, 2)

    def test_is_likely_safe_accepts_benign_stacked_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stacked.pkl"
            for count in (1, 2):
                with self.subTest(count=count):
                    path.write_bytes(pickle.dumps({"label": 1}) * count)
                    self.assertTrue(is_likely_safe(str(path)))
