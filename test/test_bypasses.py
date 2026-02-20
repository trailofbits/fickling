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
    # https://github.com/trailofbits/fickling/security/advisories/GHSA-q5qq-mvfm-j35x
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
                op.Proto.create(5),
                op.ShortBinUnicode("pydoc"),
                op.Memoize(),
                op.ShortBinUnicode("locate"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("os.system"),
                op.Memoize(),
                op.TupleOne(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("id"),
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
            "from pydoc import locate",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-q5qq-mvfm-j35x
    def test_missing_importlib(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.ShortBinUnicode("builtins"),
                op.Memoize(),
                op.ShortBinUnicode("getattr"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("importlib"),
                op.Memoize(),
                op.ShortBinUnicode("import_module"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("os"),
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
                op.ShortBinUnicode("id"),
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
            "from importlib import import_module",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-q5qq-mvfm-j35x
    def test_missing_code(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.ShortBinUnicode("builtins"),
                op.Memoize(),
                op.ShortBinUnicode("getattr"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinUnicode("code"),
                op.Memoize(),
                op.ShortBinUnicode("InteractiveInterpreter"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.EmptyTuple(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode("runsource"),
                op.Memoize(),
                op.TupleTwo(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.ShortBinUnicode('import os; os.system("id")'),
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
            "from code import InteractiveInterpreter",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-q5qq-mvfm-j35x
    def test_missing_multiprocessing(self):
        pickled = Pickled(
            [
                op.Proto.create(5),
                op.Frame(74),
                op.ShortBinUnicode("multiprocessing.util"),
                op.Memoize(),
                op.ShortBinUnicode("spawnv_passfds"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.ShortBinBytes(b"/bin/sh"),
                op.Memoize(),
                op.EmptyList(),
                op.Memoize(),
                op.Mark(),
                op.BinGet(3),
                op.ShortBinBytes(b"-c"),
                op.Memoize(),
                op.ShortBinBytes(b"id"),
                op.Memoize(),
                op.Appends(),
                op.EmptyTuple(),
                op.TupleThree(),
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
            "from multiprocessing.util import spawnv_passfds",
        )

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-h4rm-mm56-xf63
    def test_builtins_import_bypass(self):
        pickled = Pickled(
            [
                op.Global("builtins __import__"),
                op.String("os"),
                op.TupleOne(),
                op.Reduce(),
                op.Put(0),
                op.Pop(),
                op.Global("builtins getattr"),
                op.Get(0),
                op.String("system"),
                op.TupleTwo(),
                op.Reduce(),
                op.Put(1),
                op.Pop(),
                op.Get(1),
                op.String("whoami"),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        self.assertEqual(
            res.detailed_results()["AnalysisResult"].get("UnsafeImports"),
            "from builtins import getattr",
        )

    def test_safe_builtins_not_flagged(self):
        """Safe builtins like len, dict should not be flagged as malicious."""
        pickled = Pickled(
            [
                op.Global("builtins len"),
                op.EmptyList(),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        # Should not have UnsafeImports or UnsafeImportsML result for safe builtins
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNone(detailed.get("UnsafeImports"))
        self.assertIsNone(detailed.get("UnsafeImportsML"))

    def test_safe_builtin_dict_not_flagged(self):
        """Safe builtin dict() should not be flagged as malicious."""
        pickled = Pickled(
            [
                op.Global("builtins dict"),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNone(detailed.get("UnsafeImports"))
        self.assertIsNone(detailed.get("UnsafeImportsML"))

    def test_unsafe_builtins_still_flagged(self):
        """Dangerous builtins like getattr, __import__ must still be flagged."""
        pickled = Pickled(
            [
                op.Global("builtins getattr"),
                op.String("os"),
                op.String("system"),
                op.TupleTwo(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        # Should be flagged by both unsafe import checkers
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNotNone(detailed.get("UnsafeImports"))
        self.assertIsNotNone(detailed.get("UnsafeImportsML"))

    def test_unsafe_builtin_eval_still_flagged(self):
        """Dangerous builtin eval must still be flagged."""
        pickled = Pickled(
            [
                op.Global("builtins eval"),
                op.String("print('hello')"),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)
        # Should be flagged by both unsafe import checkers
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNotNone(detailed.get("UnsafeImports"))
        self.assertIsNotNone(detailed.get("UnsafeImportsML"))

    # https://github.com/mmaitre314/picklescan/security/advisories/GHSA-955r-x9j8-7rhh
    def test_operator_methodcaller(self):
        """Test detection of _operator.methodcaller bypass."""
        pickled = Pickled(
            [
                op.Global.create("builtins", "__import__"),
                op.Mark(),
                op.Unicode("os"),
                op.Tuple(),
                op.Reduce(),
                op.Put(0),
                op.Pop(),
                op.Global.create("_operator", "methodcaller"),
                op.Mark(),
                op.Unicode("system"),
                op.Unicode('echo "pwned by _operator.methodcaller"'),
                op.Tuple(),
                op.Reduce(),
                op.Mark(),
                op.Get(0),
                op.Tuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)

    # https://github.com/mmaitre314/picklescan/security/advisories/GHSA-m273-6v24-x4m4
    def test_distutils_write_file(self):
        """Test detection of distutils.file_util.write_file bypass."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("distutils.file_util"),
                op.ShortBinUnicode("write_file"),
                op.StackGlobal(),
                op.ShortBinUnicode("/tmp/malicious.txt"),
                op.Mark(),
                op.ShortBinUnicode("malicious content"),
                op.List(),
                op.TupleTwo(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)

    def test_io_fileio(self):
        """Test detection of _io.FileIO bypass."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("_io"),
                op.ShortBinUnicode("FileIO"),
                op.StackGlobal(),
                op.ShortBinUnicode("/etc/passwd"),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)

    # https://github.com/mmaitre314/picklescan/security/advisories/GHSA-r8g5-cgf2-4m4m
    def test_numpy_f2py_getlincoef(self):
        """Test detection of numpy.f2py.crackfortran.getlincoef bypass."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("numpy.f2py.crackfortran"),
                op.ShortBinUnicode("getlincoef"),
                op.StackGlobal(),
                op.ShortBinUnicode("__import__('os').system('id')"),
                op.EmptyDict(),
                op.TupleTwo(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)

    def test_network_protocol_ssrf(self):
        cases = [
            ("smtplib", "SMTP", 25),
            ("imaplib", "IMAP4", 143),
            ("ftplib", "FTP", 21),
            ("poplib", "POP3", 110),
            ("telnetlib", "Telnet", 23),
            ("nntplib", "NNTP", 119),
        ]
        for module, cls, port in cases:
            with self.subTest(module=module):
                pickled = Pickled(
                    [
                        op.Proto.create(4),
                        op.Global.create(module, cls),
                        op.ShortBinUnicode("127.0.0.1"),
                        op.BinInt2(port),
                        op.TupleTwo(),
                        op.Reduce(),
                        op.EmptyDict(),
                        op.Build(),
                        op.Stop(),
                    ]
                )
                res = check_safety(pickled)
                self.assertGreater(
                    res.severity,
                    Severity.LIKELY_SAFE,
                    f"{module}.{cls} was not flagged as unsafe",
                )

    # https://github.com/mmaitre314/picklescan/security/advisories/GHSA-f7qq-56ww-84cr
    def test_asyncio_subprocess(self):
        """Test detection of asyncio subprocess execution bypass."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.Frame(81),
                op.ShortBinUnicode("asyncio.unix_events"),
                op.Memoize(),
                op.ShortBinUnicode("_UnixSubprocessTransport._start"),
                op.Memoize(),
                op.StackGlobal(),
                op.Memoize(),
                op.Mark(),
                op.EmptyDict(),
                op.Memoize(),
                op.ShortBinUnicode("whoami"),
                op.Memoize(),
                op.NewTrue(),
                op.NoneOpcode(),
                op.NoneOpcode(),
                op.NoneOpcode(),
                op.BinInt1(0),
                op.Tuple(),
                op.Memoize(),
                op.Reduce(),
                op.Memoize(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(res.severity, Severity.LIKELY_SAFE)

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-mxhj-88fx-4pcv
    def test_obj_pop_call_invisibility(self):
        """OBJ opcode calls discarded by POP must remain visible to safety analysis."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.Mark(),
                op.ShortBinUnicode("smtplib"),
                op.ShortBinUnicode("SMTP"),
                op.StackGlobal(),
                op.ShortBinUnicode("127.0.0.1"),
                op.Obj(),
                op.Pop(),
                op.NoneOpcode(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertGreater(
            res.severity,
            Severity.LIKELY_SAFE,
        )
