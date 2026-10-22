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
