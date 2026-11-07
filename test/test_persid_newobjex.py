"""
Regression tests for two analysis crashes: PERSID had no interpreter step (NotImplementedError)
and NEWOBJ_EX passed its kwargs expression as `ast.Call.keywords` (TypeError in check_safety).

Payloads are built with Python's pickle module or fickling's opcode API. Nothing here is ever
unpickled: the dangerous names below are references only (a global that is never called).
"""

import ast
import collections
import io
import linecache
import pickle
import pickletools
from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class _PersistentIdPickler(pickle.Pickler):
    """Pickler that stores one sentinel object by persistent id."""

    SENTINEL = object()

    def persistent_id(self, obj):
        return "0" if obj is self.SENTINEL else None


def _persid_dumps(obj, protocol):
    """Protocol 0 emits PERSID; protocols 1 and above emit BINPERSID for the same object."""
    buf = io.BytesIO()
    _PersistentIdPickler(buf, protocol=protocol).dump([_PersistentIdPickler.SENTINEL, obj])
    return buf.getvalue()


def _opcodes(data):
    return {opcode.name for opcode, _, _ in pickletools.genops(data)}


def _newobj_ex(module, name, kwargs):
    return Pickled(
        [
            op.Proto.create(4),
            op.Global.create(module, name),
            op.EmptyTuple(),
            op.EmptyDict(),
            *kwargs,
            op.NewObjEx(),
            op.Stop(),
        ]
    )


class TestPersIdNewObjEx(TestCase):
    def test_persid_is_analysed_like_binpersid(self):
        for tail in (collections.OrderedDict(), linecache.getlines):
            with self.subTest(tail=tail):
                text, binary = _persid_dumps(tail, 0), _persid_dumps(tail, 2)
                self.assertIn("PERSID", _opcodes(text))
                self.assertIn("BINPERSID", _opcodes(binary))
                self.assertEqual(
                    check_safety(Pickled.load(text)).severity,
                    check_safety(Pickled.load(binary)).severity,
                )

    def test_persid_call_survives_pop(self):
        # PERSID, POP, NONE, STOP: a custom unpickler still runs persistent_load, so the
        # call must stay in the AST even though its stack value is discarded.
        pickled = Pickled.load(b"Pabc\n0N.")
        self.assertEqual(
            [opcode.name for opcode in pickled],
            ["PERSID", "POP", "NONE", "STOP"],
        )
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("UNPICKLER.persistent_load('abc')"), 1, source)

    def test_persid_call_is_not_repeated_by_memo_reuse(self):
        # PERSID, PUT 0, POP, MARK, GET 0, GET 0, TUPLE, STOP: one load, referenced twice.
        pickled = Pickled.load(b"Pabc\np0\n0(g0\ng0\nt.")
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("persistent_load("), 1, source)

    def test_persid_valid_single_use_keeps_one_call(self):
        # PERSID, STOP: the common benign shape still yields exactly one persistent_load call.
        pickled = Pickled.load(b"Pabc\n.")
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("UNPICKLER.persistent_load('abc')"), 1, source)
        self.assertIsNotNone(check_safety(pickled).severity)

    def test_binpersid_call_survives_pop(self):
        # STRING, BINPERSID, POP, NONE, STOP: same invariant as PERSID for the binary form.
        pickled = Pickled.load(b"S'abc'\nQ0N.")
        self.assertEqual(
            [opcode.name for opcode in pickled],
            ["STRING", "BINPERSID", "POP", "NONE", "STOP"],
        )
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("UNPICKLER.persistent_load('abc')"), 1, source)

    def test_binpersid_call_is_not_repeated_by_memo_reuse(self):
        # STRING, BINPERSID, PUT 0, POP, MARK, GET 0, GET 0, TUPLE, STOP: one load, used twice.
        pickled = Pickled.load(b"S'abc'\nQp0\n0(g0\ng0\nt.")
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("persistent_load("), 1, source)

    def test_binpersid_valid_single_use_keeps_one_call(self):
        # STRING, BINPERSID, STOP: the common benign shape still yields exactly one call.
        pickled = Pickled.load(b"S'abc'\nQ.")
        source = ast.unparse(pickled.ast)
        self.assertEqual(source.count("UNPICKLER.persistent_load('abc')"), 1, source)
        self.assertIsNotNone(check_safety(pickled).severity)

    def test_newobj_ex_is_analysed_and_unparses(self):
        cases = {
            "empty kwargs": [],
            "one kwarg": [op.ShortBinUnicode("k"), op.BinInt1(1), op.SetItem()],
        }
        for label, kwargs in cases.items():
            with self.subTest(kwargs=label):
                pickled = _newobj_ex("collections", "OrderedDict", kwargs)
                # NEWOBJ_EX is reported like NEWOBJ
                self.assertGreaterEqual(check_safety(pickled).severity, Severity.LIKELY_UNSAFE)
                ast.unparse(pickled.ast)

    def test_newobj_ex_still_flags_dangerous_class(self):
        pickled = _newobj_ex("linecache", "getlines", [])
        self.assertGreaterEqual(check_safety(pickled).severity, Severity.LIKELY_UNSAFE)
