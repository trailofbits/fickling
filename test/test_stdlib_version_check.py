"""
Regression test for stdlib module names version independence (closes #311).

Before the fix, BUILTIN_STDLIB_MODULE_NAMES was set to
sys.stdlib_module_names which varies across Python versions.
A pickle scanned on Python 3.11 CI but loaded on a developer's
Python 3.12 machine could get different stdlib classification.

The static union is also guarded against drift: every module in the running
interpreter's stdlib must be covered, and modules removed from the stdlib in a
recent version are reported as shadowable (a PyPI package may reuse the name)
unless explicitly allowlisted.
"""

import sys

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import (
    BUILTIN_STDLIB_MODULE_NAMES,
    SHADOWED_STDLIB_IMPORT_ALLOWLIST,
    SHADOWED_STDLIB_MODULE_NAMES,
)


def _pickle_with_import(module: str, name: str = "attr") -> op.Pickled:
    return op.Pickled(
        [
            op.Proto.create(4),
            op.ShortBinUnicode(module),
            op.ShortBinUnicode(name),
            op.StackGlobal(),
            op.Stop(),
        ]
    )


class TestStdlibModuleNames:
    """Stdlib module names must be version-independent."""

    def test_contains_common_stdlib_modules(self):
        """All common stdlib modules must be in the set."""
        common = {
            "os",
            "sys",
            "json",
            "pickle",
            "subprocess",
            "importlib",
            "collections",
            "functools",
            "pathlib",
            "typing",
            "abc",
            "io",
            "re",
            "math",
            "datetime",
            "logging",
            "unittest",
        }
        for mod in common:
            assert mod in BUILTIN_STDLIB_MODULE_NAMES, (
                f"{mod} should be in BUILTIN_STDLIB_MODULE_NAMES"
            )

    def test_contains_legacy_modules(self):
        """Legacy modules removed in newer Python must still be listed."""
        for mod in SHADOWED_STDLIB_MODULE_NAMES:
            assert mod in BUILTIN_STDLIB_MODULE_NAMES, (
                f"Shadowed module {mod} should be in BUILTIN_STDLIB_MODULE_NAMES"
            )

    def test_is_frozenset(self):
        """Must be a frozenset for immutability."""
        assert isinstance(BUILTIN_STDLIB_MODULE_NAMES, frozenset)
        assert isinstance(SHADOWED_STDLIB_MODULE_NAMES, frozenset)
        assert isinstance(SHADOWED_STDLIB_IMPORT_ALLOWLIST, frozenset)

    def test_not_empty(self):
        """Must not be empty."""
        assert len(BUILTIN_STDLIB_MODULE_NAMES) > 100
        assert len(SHADOWED_STDLIB_MODULE_NAMES) > 10

    def test_independent_of_runtime_version(self):
        """The set must include modules from multiple Python versions."""
        # tomllib was added in 3.11
        assert "tomllib" in BUILTIN_STDLIB_MODULE_NAMES
        # graphlib was added in 3.9 but is still stdlib
        assert "graphlib" in BUILTIN_STDLIB_MODULE_NAMES

    def test_no_drift_from_runtime_stdlib(self):
        """Every stdlib module of the running interpreter must be covered.

        This is the CI drift guard: when a future Python version adds a new
        stdlib module, this test fails until BUILTIN_STDLIB_MODULE_NAMES is
        updated, instead of silently producing version-dependent
        classification.
        """
        missing = set(sys.stdlib_module_names) - BUILTIN_STDLIB_MODULE_NAMES
        assert not missing, (
            "BUILTIN_STDLIB_MODULE_NAMES is missing stdlib modules present on "
            f"Python {sys.version_info.major}.{sys.version_info.minor}: "
            f"{sorted(missing)}"
        )


class TestShadowedStdlibImports:
    """Removed stdlib modules must not be silently trusted."""

    def test_current_stdlib_import_is_safe(self):
        results = check_safety(_pickle_with_import("json"))
        assert results.severity == Severity.LIKELY_SAFE

    def test_shadowed_stdlib_import_is_reported(self):
        results = check_safety(_pickle_with_import("cgi"))
        assert results.severity >= Severity.SUSPICIOUS
        names = {r.analysis_name for r in results.results}
        assert "ShadowedStdlibImports" in names

    def test_allowlisted_shadowed_import_is_safe(self, monkeypatch):
        monkeypatch.setattr(op, "SHADOWED_STDLIB_IMPORT_ALLOWLIST", frozenset({"cgi"}))
        results = check_safety(_pickle_with_import("cgi"))
        assert results.severity == Severity.LIKELY_SAFE
