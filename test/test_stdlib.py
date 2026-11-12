"""Tests for version-independent stdlib-membership checks (issue #311).

The stdlib checks must not depend on the interpreter running the scanner:
scan results for the same pickle must be identical on every supported
Python version.
"""

import io
import sys
import tempfile
import unittest
from pathlib import Path

import fickling.fickle as op
from fickling.cli import main
from fickling.constants import EXIT_CLEAN, EXIT_UNSAFE
from fickling.fickle import (
    BUILTIN_STDLIB_MODULE_NAMES,
    Pickled,
    is_private_or_dunder_stdlib_module,
    is_std_module,
    reset_stdlib_module_names,
    set_stdlib_module_names,
)
from fickling.stdlib import STDLIB_MODULE_NAMES, STDLIB_MODULE_NAMES_BY_VERSION


def import_from_pickle(module: str, name: str) -> Pickled:
    """Build a Pickled whose AST is `from <module> import <name>`."""
    return Pickled(
        [
            op.Proto.create(4),
            op.ShortBinUnicode(module),
            op.ShortBinUnicode(name),
            op.StackGlobal(),
            op.Stop(),
        ]
    )


class TestStdlibTables(unittest.TestCase):
    def test_union_covers_modules_added_after_310(self):
        # tomllib (3.11+), _interpreters (3.13+) must count as stdlib
        # even though older interpreters lack them.
        self.assertIn("tomllib", STDLIB_MODULE_NAMES)
        self.assertIn("_interpreters", STDLIB_MODULE_NAMES)

    def test_union_covers_modules_removed_before_314(self):
        # imp (removed 3.12) and pipes (removed 3.13) were stdlib in
        # supported versions, so the union keeps them.
        self.assertIn("imp", STDLIB_MODULE_NAMES)
        self.assertIn("pipes", STDLIB_MODULE_NAMES)

    def test_running_interpreter_stdlib_is_subset_of_union(self):
        # Whatever interpreter runs the scanner, its own stdlib must be
        # covered by the version-independent default.
        self.assertLessEqual(set(sys.stdlib_module_names), STDLIB_MODULE_NAMES)

    def test_builtin_alias_is_the_default_union(self):
        self.assertEqual(BUILTIN_STDLIB_MODULE_NAMES, STDLIB_MODULE_NAMES)

    def test_per_version_tables_are_subsets_of_union(self):
        for version, names in STDLIB_MODULE_NAMES_BY_VERSION.items():
            with self.subTest(version=version):
                self.assertLessEqual(names, STDLIB_MODULE_NAMES)

    def test_supported_versions_present(self):
        self.assertEqual(
            sorted(STDLIB_MODULE_NAMES_BY_VERSION), ["3.10", "3.11", "3.12", "3.13", "3.14"]
        )


class TestVersionIndependentChecks(unittest.TestCase):
    def test_private_module_from_newer_python_is_flagged(self):
        # _interpreters only exists on 3.13+. On older scanners the old
        # sys.stdlib_module_names-based check missed it entirely.
        if sys.version_info < (3, 13):
            self.assertNotIn("_interpreters", sys.stdlib_module_names)
        self.assertTrue(is_private_or_dunder_stdlib_module("_interpreters"))
        pickled = import_from_pickle("_interpreters", "create")
        self.assertEqual(len(list(pickled.private_stdlib_imports())), 1)

    def test_module_added_after_310_not_reported_as_non_standard(self):
        # On a 3.10 scanner, `from tomllib import load` was wrongly reported
        # as a non-standard import.
        if sys.version_info < (3, 11):
            self.assertNotIn("tomllib", sys.stdlib_module_names)
        pickled = import_from_pickle("tomllib", "load")
        self.assertEqual(list(pickled.non_standard_imports()), [])

    def test_removed_module_still_recognized_as_stdlib(self):
        # imp was removed in 3.12; newer scanners must still treat it as
        # stdlib for these checks.
        if sys.version_info >= (3, 12):
            self.assertNotIn("imp", sys.stdlib_module_names)
        self.assertTrue(is_std_module("imp"))


class TestTargetVersionOverride(unittest.TestCase):
    def tearDown(self):
        reset_stdlib_module_names()

    def test_set_and_reset(self):
        try:
            set_stdlib_module_names(STDLIB_MODULE_NAMES_BY_VERSION["3.10"])
            self.assertFalse(is_std_module("tomllib"))
            self.assertFalse(is_private_or_dunder_stdlib_module("_interpreters"))
            # A pickle importing a 3.11+ module is non-standard under 3.10.
            pickled = import_from_pickle("tomllib", "load")
            self.assertEqual(len(list(pickled.non_standard_imports())), 1)
        finally:
            reset_stdlib_module_names()
        self.assertTrue(is_std_module("tomllib"))
        self.assertTrue(is_private_or_dunder_stdlib_module("_interpreters"))

    def test_set_accepts_any_iterable(self):
        try:
            set_stdlib_module_names(["os", "sys"])
            self.assertTrue(is_std_module("os"))
            self.assertFalse(is_std_module("tomllib"))
        finally:
            reset_stdlib_module_names()

    def test_set_rejects_a_bare_string(self):
        with self.assertRaises(TypeError):
            set_stdlib_module_names("3.10")


class TestTargetPythonVersionFlag(unittest.TestCase):
    def _pickle_file(self, module: str, name: str) -> Path:
        pickled = import_from_pickle(module, name)
        tmp = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False)
        try:
            buffer = io.BytesIO()
            pickled.dump(buffer)
            tmp.write(buffer.getvalue())
        finally:
            tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return Path(tmp.name)

    def tearDown(self):
        reset_stdlib_module_names()

    def test_flag_changes_non_standard_import_verdict(self):
        path = self._pickle_file("tomllib", "load")
        try:
            # Default union: tomllib is stdlib -> clean.
            self.assertEqual(main(["fickling", "--check-safety", str(path)]), EXIT_CLEAN)
            # Targeting 3.10: tomllib is not stdlib -> unsafe.
            self.assertEqual(
                main(["fickling", "--check-safety", "--target-python-version", "3.10", str(path)]),
                EXIT_UNSAFE,
            )
        finally:
            reset_stdlib_module_names()

    def test_flag_rejects_unknown_version(self):
        with self.assertRaises(SystemExit):
            main(["fickling", "--check-safety", "--target-python-version", "2.7", "x"])


if __name__ == "__main__":
    unittest.main()
