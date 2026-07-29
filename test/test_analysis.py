from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestAnalysis(TestCase):
    def test_benign_pickle(self):
        for module, name in (("collections", "deque"), ("collections.abc", "Iterable")):
            with self.subTest(module=module):
                pickled = Pickled(
                    [
                        op.Proto.create(4),
                        op.ShortBinUnicode(module),
                        op.ShortBinUnicode(name),
                        op.StackGlobal(),
                        op.Stop(),
                    ]
                )
                self.assertEqual(check_safety(pickled).severity, Severity.LIKELY_SAFE)
