from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import (
    Analyzer,
    UnsafeImports,
    UnsafeImportsML,
    check_safety,
)
from fickling.fickle import Pickled


class TestImportMatchingGaps(TestCase):
    """Regression tests for gaps in how analysis passes handle imports."""

    def test_stdlib_submodule_not_flagged_as_nonstandard(self):
        """Stdlib submodules like collections.abc should not trigger NonStandardImports."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.Global.create("collections.abc", "Mapping"),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        result = check_safety(pickled)
        non_std_results = [r for r in result.results if r.analysis_name == "NonStandardImports"]
        self.assertEqual(
            len(non_std_results),
            0,
            "collections.abc should not be flagged as non-standard",
        )

    def test_eval_import_from_unsafe_imports_ml_module(self):
        """Eval check must not be skipped when module is in UNSAFE_IMPORTS.

        Not a real payload (_io.eval doesn't exist), just a regression trigger.
        """
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("_io"),
                op.ShortBinUnicode("eval"),
                op.StackGlobal(),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        result = check_safety(pickled)
        eval_results = [
            r
            for r in result.results
            if r.analysis_name == "UnsafeImportsML" and "eval" in (r.message or "")
        ]
        self.assertGreater(
            len(eval_results),
            0,
            "UnsafeImportsML should flag 'from _io import eval'",
        )

    def test_ext1_ast_import_does_not_crash_analysis(self):
        """Ext1 generates ast.Import nodes; both analysis passes must handle them."""
        pickled = Pickled(
            [
                op.Proto.create(2),
                op.Ext1(1),
                op.Stop(),
            ]
        )
        # Must not raise AttributeError: 'Import' object has no attribute 'module'
        for analysis in [UnsafeImportsML(), UnsafeImports()]:
            with self.subTest(analysis=type(analysis).__name__):
                result = Analyzer([analysis]).analyze(pickled)
                self.assertIsNotNone(result)
