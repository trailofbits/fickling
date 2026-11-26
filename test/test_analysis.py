import pickle
from collections import defaultdict
from functools import partial
from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestAnalysis(TestCase):
    def test_starmap_callback(self):
        pickled = Pickled(
            [
                op.Global.create("itertools", "starmap"),
                op.Global.create("builtins", "int"),
                op.EmptyTuple(),
                op.TupleTwo(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        result = check_safety(pickled)
        self.assertEqual(result.severity, Severity.POSSIBLY_UNSAFE)
        self.assertIn("CallbackArguments", [r.analysis_name for r in result.results])

    def test_defaultdict_factories(self):
        for protocol in (2, 4):
            for factory in (list, int, set, None):
                with self.subTest(protocol=protocol, factory=factory):
                    pickled = Pickled.load(pickle.dumps(defaultdict(factory), protocol=protocol))
                    result = check_safety(pickled)
                    self.assertNotIn("CallbackArguments", [r.analysis_name for r in result.results])
                    if protocol == 4:
                        self.assertEqual(result.severity, Severity.LIKELY_SAFE)

    def test_computed_factory(self):
        pickled = Pickled.load(pickle.dumps(defaultdict(partial(int)), protocol=4))
        findings = [r.analysis_name for r in check_safety(pickled).results]
        self.assertIn("CallbackArguments", findings)

    def test_callback_from_memo_keeps_its_module(self):
        # An import of the same name after memoization cannot change the stored factory.
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.Global.create("example", "list"),
                op.Memoize(),
                op.Pop(),
                op.Global.create("builtins", "list"),
                op.Pop(),
                op.ShortBinUnicode("collections"),
                op.ShortBinUnicode("defaultdict"),
                op.StackGlobal(),
                op.BinGet(0),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        findings = [
            r for r in check_safety(pickled).results if r.analysis_name == "CallbackArguments"
        ]
        self.assertEqual([r.severity for r in findings], [Severity.POSSIBLY_UNSAFE])

    def test_file_opener_reference(self):
        pickled = Pickled([op.Global.create("codecs", "open"), op.Stop()])
        self.assertEqual(check_safety(pickled).severity, Severity.LIKELY_OVERTLY_MALICIOUS)

    def test_benign_pickle(self):
        for module, name in (
            ("collections", "deque"),
            ("collections.abc", "Iterable"),
            ("itertools", "starmap"),
        ):
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

    # EXT opcodes generate ast.Import nodes, which have no module attribute.
    def test_extension_opcodes_do_not_crash_analysis(self):
        for opcode in (op.Ext1, op.Ext2, op.Ext4):
            with self.subTest(opcode=opcode.name):
                pickled = Pickled([op.Proto.create(2), opcode(1), op.Stop()])
                self.assertGreater(check_safety(pickled).severity, Severity.LIKELY_SAFE)
