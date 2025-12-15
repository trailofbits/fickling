from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestBypasses(TestCase):
    # https://github.com/trailofbits/fickling/security/advisories/GHSA-r7v6-mfhq-g3m2
    def test_missing_pty_unsafe_imports_ghsa(self):
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.Frame(26),
                op.ShortBinUnicode("pty"),
                op.Memoize(),
                op.ShortBinUnicode("spawn"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("id"),
                op.Memoize(),
                op.TupleOne(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("gottem"),
                op.Memoize(),
                op.Build(),
                op.Stop(),
            ]
        )
        self.assertGreater(check_safety(pickled).severity, Severity.LIKELY_SAFE)

    # https://github.com/trailofbits/fickling/pull/108
    def test_missing_pty_unsafe_imports_pr(self):
        pickled = Pickled(
            [
                op.Mark(),
                op.Global("pty spawn"),
                op.String("id"),
                op.Obj(),
                op.Stop(),
            ]
        )
        self.assertGreater(check_safety(pickled).severity, Severity.LIKELY_SAFE)
