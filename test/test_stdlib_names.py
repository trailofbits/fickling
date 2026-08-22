import sys
from unittest import TestCase

from fickling import stdlib_names
from fickling.fickle import is_private_or_dunder_stdlib_module, is_std_module


class TestStdlibNameUnion(TestCase):
    def test_removed_modules_still_recognized(self):
        """Modules removed from recent Pythons must still count as stdlib when
        the scanner runs on an interpreter that no longer ships them (issue
        #311): a pickle importing `asynchat` is benign on 3.10/3.11 targets,
        and the scanner cannot assume its own version matches the loader's.
        """
        for removed in ("asynchat", "asyncore", "imp", "smtpd", "distutils"):
            self.assertTrue(is_std_module(removed), removed)

    def test_future_modules_always_recognized(self):
        """Names that only exist in newer supported versions must be treated
        as stdlib even when this interpreter predates them."""
        for added in ("tomllib", "graphlib", "annotationlib", "compression"):
            self.assertTrue(
                is_std_module(added),
                f"{added} missing from union (scanner: {sys.version_info[:2]})",
            )

    def test_nonstdlib_names_still_flagged(self):
        self.assertFalse(is_std_module("definitely_not_a_module_xyz"))
        self.assertFalse(is_std_module("os_malicious_squat"))

    def test_top_level_component_semantics(self):
        """Only the top-level package decides; submodules inherit (unchanged
        pre-existing behavior)."""
        self.assertTrue(is_std_module("os.path"))
        self.assertFalse(is_std_module("evil.os"))

    def test_dunder_and_private_modules(self):
        self.assertTrue(is_private_or_dunder_stdlib_module("_socket"))
        self.assertTrue(is_private_or_dunder_stdlib_module("__future__"))
        self.assertFalse(is_private_or_dunder_stdlib_module("socket"))
        self.assertFalse(is_private_or_dunder_stdlib_module("_not_in_stdlib_at_all"))

    def test_per_version_tables_are_real_data(self):
        # Sanity-check provenance: every version table contains `sys` and
        # `pickle`, and version-specific additions/removals are where CPython
        # put them.
        for names in stdlib_names.STDLIB_MODULE_NAMES_BY_VERSION.values():
            self.assertIn("sys", names)
            self.assertIn("pickle", names)
        v310 = stdlib_names.STDLIB_MODULE_NAMES_BY_VERSION["3.10"]
        v311 = stdlib_names.STDLIB_MODULE_NAMES_BY_VERSION["3.11"]
        v314 = stdlib_names.STDLIB_MODULE_NAMES_BY_VERSION["3.14"]
        self.assertIn("imp", v310)
        self.assertNotIn("imp", v314)
        self.assertNotIn("tomllib", v310)
        self.assertIn("tomllib", v311)
        self.assertIn("annotationlib", v314)

    def test_union_covers_every_table(self):
        union = stdlib_names.STDLIB_MODULE_NAMES_UNION
        for version, names in stdlib_names.STDLIB_MODULE_NAMES_BY_VERSION.items():
            self.assertTrue(
                names <= union,
                f"{version} has names missing from the union",
            )

    def test_running_interpreter_names_included(self):
        self.assertTrue(
            set(sys.stdlib_module_names) <= stdlib_names.STDLIB_MODULE_NAMES
        )

    def test_use_stdlib_of_narrows_and_restores(self):
        try:
            narrowed = stdlib_names.use_stdlib_of("3.10")
            self.assertIn("imp", narrowed)
            self.assertNotIn("tomllib", narrowed)
            # The narrowing is visible through fickling.fickle predicates.
            self.assertTrue(is_std_module("imp"))
            self.assertFalse(is_std_module("tomllib"))
        finally:
            restored = stdlib_names.use_stdlib_of()
            self.assertIn("tomllib", restored)
            self.assertTrue(is_std_module("tomllib"))

    def test_use_stdlib_of_rejects_unknown_versions(self):
        with self.assertRaises(KeyError):
            stdlib_names.use_stdlib_of("9.9")


class TestShadowedStdlibImports(TestCase):
    @staticmethod
    def _pickled_importing(module: str):
        import fickling.fickle as op
        from fickling.fickle import Pickled

        return Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode(module),
                op.ShortBinUnicode("attr"),
                op.StackGlobal(),
                op.Stop(),
            ]
        )

    def test_removed_name_import_is_shadow_flagged(self):
        from fickling.analysis import Severity, check_safety

        result = check_safety(self._pickled_importing("asynchat"))
        self.assertEqual(result.severity, Severity.SUSPICIOUS)

    def test_live_stdlib_name_not_shadow_flagged(self):
        from fickling.analysis import Severity, check_safety

        result = check_safety(self._pickled_importing("collections"))
        self.assertEqual(result.severity, Severity.LIKELY_SAFE)

    def test_current_target_ships_removed_module(self):
        """Narrowing to a version that still ships the module silences the
        shadow warning."""
        from fickling.analysis import Severity, check_safety
        from fickling.fickle import is_shadowed_stdlib_module

        try:
            stdlib_names.use_stdlib_of("3.10")
            self.assertFalse(is_shadowed_stdlib_module("asynchat"))
            self.assertEqual(
                check_safety(self._pickled_importing("asynchat")).severity,
                Severity.LIKELY_SAFE,
            )
        finally:
            stdlib_names.use_stdlib_of()
        self.assertTrue(is_shadowed_stdlib_module("asynchat"))

    def test_allowlist_restores_benign_classification(self):
        import fickling.fickle as fickle_module
        from fickling.analysis import Severity, check_safety

        try:
            # chunk is shadowable but not on the hard UNSAFE_IMPORTS list,
            # so the allowlist alone flips it back to benign.
            fickle_module.SHADOWED_STDLIB_IMPORT_ALLOWLIST = frozenset({"chunk"})
            self.assertFalse(fickle_module.is_shadowed_stdlib_module("chunk"))
            self.assertTrue(fickle_module.is_shadowed_stdlib_module("imp"))
            self.assertEqual(
                check_safety(self._pickled_importing("chunk")).severity,
                Severity.LIKELY_SAFE,
            )
        finally:
            fickle_module.SHADOWED_STDLIB_IMPORT_ALLOWLIST = frozenset()
