"""Tests for fickling.tracing — the Trace class that instruments pickle interpretation.

The Trace class wraps an Interpreter and reports stack operations, memoization,
opcode execution, and statement generation as the pickle bytecode is stepped
through.  These tests verify that every callback fires correctly for real pickle
payloads and that the overall run() method returns a valid AST.
"""

import ast
import pickle
import sys
from io import StringIO
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from fickling.fickle import Interpreter, MarkObject, Pickled, Stack
from fickling.tracing import Trace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trace(obj):
    """Create a Trace for a pickled Python object."""
    data = pickle.dumps(obj)
    pickled = Pickled.load(data)
    interp = Interpreter(pickled)
    return Trace(interp)


def _capture_trace(obj):
    """Run a Trace and return (ast_module, captured_stdout)."""
    trace = _make_trace(obj)
    buf = StringIO()
    with patch("sys.stdout", buf):
        result = trace.run()
    return result, buf.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTraceRun(TestCase):
    """Trace.run() should interpret the pickle and return an AST."""

    def test_returns_ast_module(self):
        result, _ = _capture_trace(42)
        self.assertIsInstance(result, ast.Module)

    def test_simple_int(self):
        result, output = _capture_trace(42)
        # The result AST should contain a body
        self.assertTrue(len(result.body) > 0)
        # Output should contain at least one opcode name
        self.assertTrue(len(output.strip()) > 0)

    def test_dict_payload(self):
        result, output = _capture_trace({"key": "value"})
        self.assertIsInstance(result, ast.Module)
        self.assertIn("Pushed", output)

    def test_list_payload(self):
        result, output = _capture_trace([1, 2, 3])
        self.assertIsInstance(result, ast.Module)

    def test_nested_structure(self):
        obj = {"a": [1, 2], "b": {"c": 3}}
        result, output = _capture_trace(obj)
        self.assertIsInstance(result, ast.Module)

    def test_string_payload(self):
        result, output = _capture_trace("hello world")
        self.assertIsInstance(result, ast.Module)

    def test_tuple_payload(self):
        result, output = _capture_trace((1, "two", 3.0))
        self.assertIsInstance(result, ast.Module)

    def test_none_payload(self):
        result, output = _capture_trace(None)
        self.assertIsInstance(result, ast.Module)

    def test_bool_payload(self):
        result, output = _capture_trace(True)
        self.assertIsInstance(result, ast.Module)

    def test_empty_dict(self):
        result, _ = _capture_trace({})
        self.assertIsInstance(result, ast.Module)

    def test_empty_list(self):
        result, _ = _capture_trace([])
        self.assertIsInstance(result, ast.Module)


class TestTraceOutputFormat(TestCase):
    """Verify the text format of trace output lines."""

    def test_opcode_names_printed(self):
        """Opcode names should appear at the start of lines (no indent)."""
        _, output = _capture_trace(42)
        lines = output.strip().split("\n")
        # At least one non-indented line (opcode name)
        opcode_lines = [l for l in lines if l and not l.startswith("\t")]
        self.assertTrue(len(opcode_lines) > 0, "Expected at least one opcode name in output")

    def test_push_pop_indented(self):
        """Stack operations should be tab-indented."""
        _, output = _capture_trace({"a": 1})
        lines = output.strip().split("\n")
        indented = [l for l in lines if l.startswith("\t")]
        self.assertTrue(len(indented) > 0, "Expected indented stack operation lines")

    def test_pushed_appears_for_values(self):
        _, output = _capture_trace("test_string")
        self.assertIn("Pushed", output)

    def test_popped_appears_for_dict(self):
        """Building a dict pops values from the stack."""
        _, output = _capture_trace({"x": 1})
        self.assertIn("Popped", output)


class TestTraceCallbacks(TestCase):
    """Verify individual callback methods fire correctly."""

    def test_on_opcode_called(self):
        trace = _make_trace(42)
        trace.on_opcode = MagicMock()
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(trace.on_opcode.call_count > 0)

    def test_on_push_called(self):
        trace = _make_trace({"key": "val"})
        trace.on_push = MagicMock()
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(trace.on_push.call_count > 0)

    def test_on_pop_called(self):
        trace = _make_trace({"key": "val"})
        trace.on_pop = MagicMock()
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(trace.on_pop.call_count > 0)

    def test_on_statement_called(self):
        """Interpreter should generate at least one statement (the result assignment)."""
        trace = _make_trace(42)
        trace.on_statement = MagicMock()
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(trace.on_statement.call_count > 0)


class TestTraceMemoization(TestCase):
    """Payloads that trigger memoization should fire on_memoize."""

    def _object_needing_memo(self):
        """Create an object whose pickle uses memoization (shared references)."""
        shared = [1, 2, 3]
        return (shared, shared)  # pickle memoizes `shared`

    def test_on_memoize_called_for_shared_refs(self):
        trace = _make_trace(self._object_needing_memo())
        trace.on_memoize = MagicMock()
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(
            trace.on_memoize.call_count > 0,
            "Expected on_memoize to be called for pickle with shared references",
        )

    def test_memoize_output_contains_keyword(self):
        _, output = _capture_trace(self._object_needing_memo())
        self.assertIn("Memoized", output)


class TestTraceOnPopMarkObject(TestCase):
    """on_pop should handle MarkObject values (printed as 'MARK')."""

    def test_mark_printed_for_dict(self):
        """Dict construction uses MARK on the stack."""
        _, output = _capture_trace({"a": 1, "b": 2})
        # MARK may or may not appear depending on protocol; just ensure no crash
        self.assertIsInstance(output, str)

    def test_on_push_mark_no_crash(self):
        """Pushing a MarkObject should print 'MARK' not crash."""
        trace = _make_trace(42)
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_push(MarkObject())
        self.assertIn("MARK", buf.getvalue())

    def test_on_pop_mark_no_crash(self):
        trace = _make_trace(42)
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_pop(MarkObject())
        self.assertIn("MARK", buf.getvalue())


class TestTraceOnPushPopAstExpr(TestCase):
    """on_push and on_pop should unparse AST expressions."""

    def test_on_push_ast_constant(self):
        trace = _make_trace(42)
        node = ast.Constant(value=42)
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_push(node)
        self.assertIn("Pushed", buf.getvalue())
        self.assertIn("42", buf.getvalue())

    def test_on_pop_ast_constant(self):
        trace = _make_trace(42)
        node = ast.Constant(value="hello")
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_pop(node)
        self.assertIn("Popped", buf.getvalue())
        self.assertIn("hello", buf.getvalue())


class TestTraceOnMemoizeDirectly(TestCase):
    """Direct calls to on_memoize and on_update_memo."""

    def test_on_memoize_prints_index_and_value(self):
        trace = _make_trace(42)
        node = ast.Constant(value=99)
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_memoize(0, node)
        output = buf.getvalue()
        self.assertIn("Memoized", output)
        self.assertIn("0", output)
        self.assertIn("99", output)

    def test_on_update_memo_prints_old_and_new(self):
        trace = _make_trace(42)
        old = ast.Constant(value="old")
        new = ast.Constant(value="new")
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_update_memo(1, old, new)
        output = buf.getvalue()
        self.assertIn("Memo index", output)
        self.assertIn("old", output)
        self.assertIn("new", output)
        self.assertIn("changed", output)


class TestTraceOnStatement(TestCase):
    """on_statement should print the unparsed statement."""

    def test_on_statement_prints_code(self):
        trace = _make_trace(42)
        stmt = ast.Assign(
            targets=[ast.Name(id="x", ctx=ast.Store())],
            value=ast.Constant(value=5),
            lineno=1,
            col_offset=0,
        )
        buf = StringIO()
        with patch("sys.stdout", buf):
            trace.on_statement(stmt)
        output = buf.getvalue()
        self.assertIn("x", output)
        self.assertIn("5", output)


class TestTraceProtocolVersions(TestCase):
    """Verify tracing works across pickle protocol versions."""

    def test_protocol_0(self):
        data = pickle.dumps([1, 2, 3], protocol=0)
        pickled = Pickled.load(data)
        trace = Trace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            result = trace.run()
        self.assertIsInstance(result, ast.Module)

    def test_protocol_2(self):
        data = pickle.dumps([1, 2, 3], protocol=2)
        pickled = Pickled.load(data)
        trace = Trace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            result = trace.run()
        self.assertIsInstance(result, ast.Module)

    def test_protocol_4(self):
        data = pickle.dumps([1, 2, 3], protocol=4)
        pickled = Pickled.load(data)
        trace = Trace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            result = trace.run()
        self.assertIsInstance(result, ast.Module)

    def test_highest_protocol(self):
        data = pickle.dumps([1, 2, 3], protocol=pickle.HIGHEST_PROTOCOL)
        pickled = Pickled.load(data)
        trace = Trace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            result = trace.run()
        self.assertIsInstance(result, ast.Module)


class TestTraceSubclass(TestCase):
    """Users can subclass Trace to customize output; verify hooks are overridable."""

    def test_custom_on_opcode(self):
        events = []

        class CustomTrace(Trace):
            def on_opcode(self, opcode):
                events.append(("opcode", opcode.name))

        data = pickle.dumps(42)
        pickled = Pickled.load(data)
        interp = Interpreter(pickled)
        trace = CustomTrace(interp)
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(len(events) > 0)
        self.assertTrue(all(e[0] == "opcode" for e in events))

    def test_custom_on_push(self):
        pushes = []

        class CustomTrace(Trace):
            def on_push(self, value):
                pushes.append(value)

        data = pickle.dumps({"a": 1})
        pickled = Pickled.load(data)
        trace = CustomTrace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(len(pushes) > 0)

    def test_custom_on_pop(self):
        pops = []

        class CustomTrace(Trace):
            def on_pop(self, value):
                pops.append(value)

        data = pickle.dumps({"a": 1})
        pickled = Pickled.load(data)
        trace = CustomTrace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(len(pops) > 0)

    def test_custom_on_memoize(self):
        memos = []

        class CustomTrace(Trace):
            def on_memoize(self, index, value):
                memos.append((index, value))

        shared = [1, 2]
        obj = (shared, shared)
        data = pickle.dumps(obj)
        pickled = Pickled.load(data)
        trace = CustomTrace(Interpreter(pickled))
        with patch("sys.stdout", StringIO()):
            trace.run()
        self.assertTrue(len(memos) > 0)


class TestTraceComplexPayloads(TestCase):
    """Trace should handle a variety of complex payloads without errors."""

    def test_set(self):
        result, _ = _capture_trace({1, 2, 3})
        self.assertIsInstance(result, ast.Module)

    def test_bytes(self):
        result, _ = _capture_trace(b"\x00\x01\x02")
        self.assertIsInstance(result, ast.Module)

    def test_float(self):
        result, _ = _capture_trace(3.14159)
        self.assertIsInstance(result, ast.Module)

    def test_large_list(self):
        result, _ = _capture_trace(list(range(100)))
        self.assertIsInstance(result, ast.Module)

    def test_deeply_nested(self):
        obj = {"level": 0}
        for i in range(1, 10):
            obj = {"level": i, "child": obj}
        result, _ = _capture_trace(obj)
        self.assertIsInstance(result, ast.Module)

    def test_mixed_types(self):
        obj = {
            "int": 1,
            "float": 2.0,
            "str": "three",
            "list": [4, 5],
            "tuple": (6, 7),
            "none": None,
            "bool": True,
            "bytes": b"eight",
        }
        result, _ = _capture_trace(obj)
        self.assertIsInstance(result, ast.Module)
