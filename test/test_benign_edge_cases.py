"""False-positive prevention tests for the UnusedVariables heuristic.

Regression coverage for https://github.com/trailofbits/fickling/issues/226:
a variable that is referenced only inside the `result = ...` expression
(the final assignment produced by `STOP`) must NOT be reported as unused.

Before the fix, `Interpreter.unused_assignments()` broke out of its loop as
soon as it encountered the `result` assignment without walking the value of
that assignment for `ast.Name` references. That caused any variable that was
only referenced via the result expression to be falsely flagged as unused.
"""

from pickle import dumps
from unittest import TestCase

import fickling.fickle as op
from fickling.fickle import Interpreter, Pickled


def _eval_call(payload: str) -> list[op.Opcode]:
    """Opcodes that build `eval(payload)` on the stack ready for REDUCE."""
    return [
        op.Global.create("builtins", "eval"),
        op.Mark(),
        op.Unicode(payload),
        op.Tuple(),
    ]


class TestUnusedVariablesResultReferences(TestCase):
    # https://github.com/trailofbits/fickling/issues/226
    def test_var_used_in_result_not_flagged(self):
        """`result = _var0` references _var0, so _var0 is NOT unused."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertEqual(len(unused), 0)

    # https://github.com/trailofbits/fickling/issues/226
    def test_var_used_multiple_times_in_result_via_memo(self):
        """`result = (_var0, _var0)` built via BINGET — both refs count.

        This mirrors the scanpy structure reported in #226: the variable
        is assigned once and then referenced multiple times in the result
        expression via the pickle memo (BINGET).
        """
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                # memo[0] = Name("_var0") (Reduce pushed this Name on the stack)
                op.BinPut(0),
                # push Name("_var0") twice via the memo, like scanpy's BINGET usage
                op.BinGet(0),
                op.BinGet(0),
                op.TupleTwo(),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertEqual(len(unused), 0)

    # https://github.com/trailofbits/fickling/issues/226
    def test_multiple_vars_used_in_result_not_flagged(self):
        """`result = (_var0, _var1)` references both vars — neither is unused."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                op.BinPut(0),
                *_eval_call("[4, 5, 6]"),
                op.Reduce(),
                op.BinPut(1),
                op.BinGet(0),
                op.BinGet(1),
                op.TupleTwo(),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertNotIn("_var1", unused)
        self.assertEqual(len(unused), 0)

    # https://github.com/trailofbits/fickling/issues/226
    def test_var_used_in_tuple_stack_slice_not_flagged(self):
        """`result = (_var0, _var0, _var0, _var0)` built via TUPLE opcode.

        The variable-arity TUPLE opcode (StackSliceOpcode) must build an
        `ast.Tuple` whose `elts` is a list, otherwise `ast.walk` will not
        recurse into the tuple elements and `_var0` will be falsely
        flagged as unused.
        """
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                op.BinPut(0),
                op.Mark(),
                op.BinGet(0),
                op.BinGet(0),
                op.BinGet(0),
                op.BinGet(0),
                op.Tuple(),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertEqual(len(unused), 0)

    # https://github.com/trailofbits/fickling/issues/226
    def test_var_used_in_dict_keys_not_flagged(self):
        """`result = {_var0: "v1", _var0: "v2"}` built via DICT opcode.

        The DICT opcode must build an `ast.Dict` whose `keys` and `values`
        are lists (not `reversed()` iterators), otherwise `ast.walk` will
        not recurse into them and `_var0` (used as a key) will be falsely
        flagged as unused.
        """
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                op.BinPut(0),
                op.Mark(),
                op.BinGet(0),
                op.Unicode("v1"),
                op.BinGet(0),
                op.Unicode("v2"),
                op.Dict(),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertEqual(len(unused), 0)

    # Regression for the fix itself: ensure the fix does not over-correct
    # and silently hide genuinely unused variables.
    def test_genuinely_unused_var_still_flagged(self):
        """`result = _var0` references _var0 but NOT _var1 — _var1 IS unused."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                *_eval_call("[1, 2, 3]"),
                op.Reduce(),
                op.BinPut(0),
                *_eval_call("[4, 5, 6]"),
                op.Reduce(),
                # discard _var1 from the stack; it is never referenced again
                op.Pop(),
                op.BinGet(0),
                op.Stop(),
            ]
        )
        unused = Interpreter(pickled).unused_variables()
        self.assertNotIn("_var0", unused)
        self.assertIn("_var1", unused)
        self.assertEqual(len(unused), 1)

    # End-to-end smoke test mirroring the original test_unused_variables
    # scenario (where `use_output_as_unpickle_result=True` makes the eval
    # result the unpickle output). After the fix, _var0 is correctly
    # recognized as used by the result expression.
    def test_insert_python_eval_replacing_result_no_false_positive(self):
        from fickling.analysis import check_safety

        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], op.Stop)
        loaded.insert_python_eval(
            "[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=True
        )
        interpreter = Interpreter(loaded)
        unused = interpreter.unused_variables()
        self.assertEqual(len(unused), 0)
        # The eval is still overtly malicious — the fix only removes the
        # false-positive unused-variable hit, not the eval detection.
        results = check_safety(loaded).to_dict()
        self.assertEqual(results["severity"], "OVERTLY_MALICIOUS")
        detailed = results["detailed_results"]["AnalysisResult"]
        self.assertNotIn("UnusedVariables", detailed)
