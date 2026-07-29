"""
Regression test for stdlib module names version independence (closes #311).

Before the fix, BUILTIN_STDLIB_MODULE_NAMES was set to
sys.stdlib_module_names which varies across Python versions.
A pickle scanned on Python 3.11 CI but loaded on a developer's
Python 3.12 machine could get different stdlib classification.
"""

import sys
import pytest
from fickling.fickle import BUILTIN_STDLIB_MODULE_NAMES


class TestStdlibModuleNames:
    """Stdlib module names must be version-independent."""

    def test_contains_common_stdlib_modules(self):
        """All common stdlib modules must be in the set."""
        common = {
            "os", "sys", "json", "pickle", "subprocess", "importlib",
            "collections", "functools", "pathlib", "typing", "abc",
            "io", "re", "math", "datetime", "logging", "unittest",
        }
        for mod in common:
            assert mod in BUILTIN_STDLIB_MODULE_NAMES, (
                f"{mod} should be in BUILTIN_STDLIB_MODULE_NAMES"
            )

    def test_contains_legacy_modules(self):
        """Legacy modules removed in newer Python must still be listed."""
        legacy = {
            "distutils", "imp", "cgi", "cgitb", "asynchat", "asyncore",
            "smtpd", "audioop", "aifc", "sndhdr", "imghdr",
        }
        for mod in legacy:
            assert mod in BUILTIN_STDLIB_MODULE_NAMES, (
                f"Legacy module {mod} should be in BUILTIN_STDLIB_MODULE_NAMES"
            )

    def test_is_frozenset(self):
        """Must be a frozenset for immutability."""
        assert isinstance(BUILTIN_STDLIB_MODULE_NAMES, frozenset)

    def test_not_empty(self):
        """Must not be empty."""
        assert len(BUILTIN_STDLIB_MODULE_NAMES) > 100

    def test_independent_of_runtime_version(self):
        """The set must include modules from multiple Python versions."""
        # tomllib was added in 3.11
        assert "tomllib" in BUILTIN_STDLIB_MODULE_NAMES
        # graphlib was added in 3.9 but is still stdlib
        assert "graphlib" in BUILTIN_STDLIB_MODULE_NAMES
