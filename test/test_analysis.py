from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import WEIGHTS_ONLY_WHITELIST, Pickled
import sys


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

    def test_weights_only_whitelist(self):
        for full_import in WEIGHTS_ONLY_WHITELIST:
            module, name = full_import.rsplit(".", 1)
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

    def test_sys_modules_tampering(self):
        module, name = "collections", "OrderedDict"
        original_file = sys.modules[module].__file__
        self.addCleanup(setattr, sys.modules[module], "__file__", original_file)
        sys.modules[module].__file__ = "./site-packages/test/collections"
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
            self.assertGreaterEqual(check_safety(pickled).severity, Severity.LIKELY_UNSAFE)
