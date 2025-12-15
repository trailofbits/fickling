import marshal
from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestBypasses(TestCase):
    # https://github.com/trailofbits/fickling/security/advisories/GHSA-565g-hwwr-4pp3
    def test_missing_marshal_and_types(self):
        code = compile('import os\nos.system("id")', "<string>", "exec")
        opcodes = Pickled(
            [
                op.Proto(4),
                op.Frame(0),
                op.ShortBinUnicode("marshal"),
                op.ShortBinUnicode("loads"),
                op.StackGlobal(),
                op.Memoize(),
                op.BinGet(0),
                op.ShortBinBytes(marshal.dumps(code)),
                op.TupleOne(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("types"),
                op.ShortBinUnicode("FunctionType"),
                op.StackGlobal(),
                op.Memoize(),
                op.BinGet(2),
                op.BinGet(1),
                op.EmptyDict(),
                op.TupleTwo(),
                op.Reduce(),
                op.Memoize(),
                op.BinGet(3),
                op.EmptyTuple(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("gottem"),
                op.Build(),
                op.Stop(),
            ]
        )

        self.assertGreater(check_safety(opcodes).severity, Severity.LIKELY_SAFE)
