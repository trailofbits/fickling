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

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-q5qq-mvfm-j35x
    # https://github.com/trailofbits/fickling/security/advisories/GHSA-5hvc-6wx8-mvv4
    def test_missing_ctypes(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.ShortBinUnicode("builtins"),
                op.Memoize(),
                op.ShortBinUnicode("getattr"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("ctypes"),
                op.Memoize(),
                op.ShortBinUnicode("CDLL"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("libc.dylib"),
                op.Memoize(),
                op.TupleOne(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("system"),
                op.Memoize(),
                op.TupleTwo(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinBytes(b"id"),
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
            "from ctypes import CDLL",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-5hvc-6wx8-mvv4
    def test_missing_pydoc(self):
        pickled = Pickled(
            [
                op.Global("pydoc locate"),
                op.String("ctypes.windll.kernel32.WinExec"),
                op.TupleOne(),
                op.Reduce(),
                op.Put(0),
                op.Pop(),
                op.Get(0),
                op.ShortBinBytes(b"calc.exe"),
                op.BinInt1(1),
                op.TupleTwo(),
                op.Reduce(),
                op.Put(1),
                op.Pop(),
                op.Global("builtins Exception"),
                op.EmptyTuple(),
                op.Reduce(),
                op.Put(2),
                op.EmptyDict(),
                op.String("rce_status"),
                op.Get(1),
                op.SetItem(),
                op.Build(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        self.assertEqual(
            res.detailed_results()["AnalysisResult"].get("UnsafeImports"),
            "from pydoc import locate",
        )
