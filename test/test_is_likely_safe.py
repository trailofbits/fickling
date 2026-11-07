import pickle
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import fickling.fickle as op
from fickling.analysis import Severity, check_safety, is_likely_safe
from fickling.fickle import EmptyPickleError, Pickled


class TestIsLikelySafe(TestCase):
    def test_is_likely_safe_rejects_unsafe_second_stream(self):
        unsafe = Pickled(
            [
                op.Proto.create(4),
                op.Global.create("os", "system"),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        self.assertGreater(check_safety(unsafe).severity, Severity.LIKELY_SAFE)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stacked.pkl"
            path.write_bytes(pickle.dumps({"label": 1}) + unsafe.dumps())
            self.assertFalse(is_likely_safe(str(path)))

    def test_is_likely_safe_accepts_benign_stacked_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stacked.pkl"
            for count in (1, 2):
                with self.subTest(count=count):
                    path.write_bytes(pickle.dumps({"label": 1}) * count)
                    self.assertTrue(is_likely_safe(str(path)))

    def test_is_likely_safe_rejects_first_stream_without_parsing_trailing_streams(self):
        first = pickle.dumps({"label": 1})
        trailing = pickle.dumps({"label": 2})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stacked.pkl"
            for tail in (trailing * 2, trailing[:-1]):
                with self.subTest(tail=tail):
                    path.write_bytes(first + tail)
                    with (
                        patch("fickling.analysis.Pickled.load", wraps=Pickled.load) as load,
                        patch(
                            "fickling.analysis.check_safety",
                            return_value=SimpleNamespace(severity=Severity.LIKELY_UNSAFE),
                        ) as scan,
                    ):
                        self.assertFalse(is_likely_safe(str(path)))
                        load.assert_called_once()
                        scan.assert_called_once()

    def test_is_likely_safe_rejects_invalid_first_stream_without_scanning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pkl"
            path.write_bytes(pickle.dumps({"label": 1})[:-1])
            with (
                patch("fickling.analysis.Pickled.load", wraps=Pickled.load) as load,
                patch("fickling.analysis.check_safety") as scan,
            ):
                self.assertFalse(is_likely_safe(str(path)))
                load.assert_called_once()
                scan.assert_not_called()

    def test_is_likely_safe_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.pkl"
            path.write_bytes(b"")
            with self.assertRaises(EmptyPickleError):
                is_likely_safe(str(path))
