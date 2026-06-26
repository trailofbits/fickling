from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import ScannerDeactivation, Severity, check_safety
from fickling.fickle import Pickled


class TestScannerDeactivationAnalysis(TestCase):
    def test_fickling_remove_hook(self):
        """Pickle calling fickling.hook.remove_hook to strip safety hooks."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("fickling.hook"),
                op.ShortBinUnicode("remove_hook"),
                op.StackGlobal(),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertEqual(res.severity, Severity.OVERTLY_MALICIOUS)
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNotNone(detailed.get("ScannerDeactivation"))

    def test_fickling_deactivate_safe_ml(self):
        """Pickle calling fickling.hook.deactivate_safe_ml_environment."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("fickling.hook"),
                op.ShortBinUnicode("deactivate_safe_ml_environment"),
                op.StackGlobal(),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertEqual(res.severity, Severity.OVERTLY_MALICIOUS)
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNotNone(detailed.get("ScannerDeactivation"))

    def test_fickling_remove_hook_via_global_opcode(self):
        """Older Global opcode path should also trigger detection."""
        pickled = Pickled(
            [
                op.Global.create("fickling.hook", "remove_hook"),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        self.assertEqual(res.severity, Severity.OVERTLY_MALICIOUS)
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNotNone(detailed.get("ScannerDeactivation"))

    def test_benign_import_not_flagged(self):
        """A benign stdlib import should not trigger ScannerDeactivation."""
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("collections"),
                op.ShortBinUnicode("OrderedDict"),
                op.StackGlobal(),
                op.EmptyTuple(),
                op.Reduce(),
                op.Stop(),
            ]
        )
        res = check_safety(pickled)
        detailed = res.detailed_results().get("AnalysisResult", {})
        self.assertIsNone(detailed.get("ScannerDeactivation"))

    def test_all_scanner_modules_covered(self):
        """Every module in SCANNER_MODULES should be detected by ScannerDeactivation."""
        for module in ScannerDeactivation.SCANNER_MODULES:
            with self.subTest(module=module):
                pickled = Pickled(
                    [
                        op.Proto.create(4),
                        op.ShortBinUnicode(module),
                        op.ShortBinUnicode("some_func"),
                        op.StackGlobal(),
                        op.EmptyTuple(),
                        op.Reduce(),
                        op.Stop(),
                    ]
                )
                res = check_safety(pickled)
                detailed = res.detailed_results().get("AnalysisResult", {})
                self.assertIsNotNone(
                    detailed.get("ScannerDeactivation"),
                    f"{module} was not detected by ScannerDeactivation",
                )
