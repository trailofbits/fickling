from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestAnalysis(TestCase):
    def test_benign_pickle(self):
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("collections"),
                op.ShortBinUnicode("deque"),
                op.StackGlobal(),
                op.Stop(),
            ]
        )
        self.assertEqual(check_safety(pickled).severity, Severity.LIKELY_SAFE)
