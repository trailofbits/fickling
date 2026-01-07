import marshal
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

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-wfq2-52f7-7qvj
    def test_missing_runpy(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.Frame(46),
                op.ShortBinUnicode("runpy"),
                op.Memoize(),
                op.ShortBinUnicode("run_path"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("/tmp/malicious.py"),
                op.Memoize(),
                op.TupleOne(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        self.assertEqual(
            res.detailed_results()["AnalysisResult"].get("UnsafeImports"),
            "from runpy import run_path",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-p523-jq9w-64x9
    def test_missing_cprofile(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.Frame(58),
                op.ShortBinUnicode("cProfile"),
                op.Memoize(),
                op.ShortBinUnicode("run"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("print('CPROFILE_RCE_CONFIRMED')"),
                op.Memoize(),
                op.TupleOne(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        self.assertEqual(
            res.detailed_results()["AnalysisResult"].get("UnsafeImports"),
            "from cProfile import run",
        )
