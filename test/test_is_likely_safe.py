import pickle
import tempfile
from pathlib import Path
from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety, is_likely_safe
from fickling.fickle import Pickled


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
