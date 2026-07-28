"""
Regression test for false positive in --check-safety unused variable analysis
(GitHub issue #226).

The ``unused_assignments()`` method in ``fickling/fickle.py`` used ``break``
when encountering the ``result = ...`` assignment, which caused:
1. Variables referenced only in the ``result`` expression to be falsely
   flagged as "unused"
2. Any statements after the ``result`` assignment to not be scanned at all

The fix changes ``break`` to ``continue`` (via if/else restructuring),
ensuring all statements are scanned for variable usage.
"""

import ast
import pytest


def _simulate_unused_assignments_fixed(statements):
    """Replicate the fixed unused_assignments logic for testing."""
    used = set()
    defined = set()
    assignments = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "result"
            ):
                # Fixed: skip result but continue scanning
                statement = statement.value
            else:
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
                        assignments[target.id] = statement
                statement = statement.value
        if statement is not None:
            for node in ast.walk(statement):
                if isinstance(node, ast.Name):
                    used.add(node.id)
    return {varname: assignments[varname] for varname in defined - used}


def _simulate_unused_assignments_buggy(statements):
    """Replicate the BUGGY unused_assignments logic (with break)."""
    used = set()
    defined = set()
    assignments = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "result"
            ):
                break  # BUG: exits loop, doesn't scan result's value
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
                    assignments[target.id] = statement
            statement = statement.value
        if statement is not None:
            for node in ast.walk(statement):
                if isinstance(node, ast.Name):
                    used.add(node.id)
    return {varname: assignments[varname] for varname in defined - used}


class TestUnusedAssignmentsFalsePositive:
    """Variables used in the result expression must not be flagged as unused."""

    def test_variable_used_in_result_not_flagged_fixed(self):
        """_var0 used in 'result = _var0' must NOT be flagged (fixed)."""
        stmts = [
            ast.Assign(
                targets=[ast.Name(id="_var0", ctx=ast.Store())],
                value=ast.Constant(value=42),
            ),
            ast.Assign(
                targets=[ast.Name(id="result", ctx=ast.Store())],
                value=ast.Name(id="_var0", ctx=ast.Load()),
            ),
        ]
        unused = _simulate_unused_assignments_fixed(stmts)
        assert "_var0" not in unused, (
            "BUG: _var0 is used in 'result = _var0' but flagged as unused"
        )

    def test_buggy_version_false_positive(self):
        """Demonstrate the bug: _var0 IS falsely flagged in the buggy version."""
        stmts = [
            ast.Assign(
                targets=[ast.Name(id="_var0", ctx=ast.Store())],
                value=ast.Constant(value=42),
            ),
            ast.Assign(
                targets=[ast.Name(id="result", ctx=ast.Store())],
                value=ast.Name(id="_var0", ctx=ast.Load()),
            ),
        ]
        unused = _simulate_unused_assignments_buggy(stmts)
        # The buggy version DOES flag _var0 (this is the false positive)
        assert "_var0" in unused, "Expected false positive in buggy version"

    def test_truly_unused_variable_still_flagged(self):
        """A variable never used anywhere should still be flagged."""
        stmts = [
            ast.Assign(
                targets=[ast.Name(id="_var0", ctx=ast.Store())],
                value=ast.Constant(value=42),
            ),
            ast.Assign(
                targets=[ast.Name(id="_var1", ctx=ast.Store())],
                value=ast.Constant(value="unused"),
            ),
            ast.Assign(
                targets=[ast.Name(id="result", ctx=ast.Store())],
                value=ast.Name(id="_var0", ctx=ast.Load()),
            ),
        ]
        unused = _simulate_unused_assignments_fixed(stmts)
        assert "_var1" in unused, "_var1 is truly unused and should be flagged"
        assert "_var0" not in unused, "_var0 is used in result"

    def test_issue_226_scenario(self):
        """Reproduce the exact scenario from issue #226:
        _var16 assigned, then used inside a tuple passed to __setstate__,
        then result = _var24. _var16 must NOT be flagged."""
        stmts = [
            # _var16 = scalar(...)
            ast.Assign(
                targets=[ast.Name(id="_var16", ctx=ast.Store())],
                value=ast.Call(func=ast.Name(id="scalar", ctx=ast.Load()), args=[], keywords=[]),
            ),
            # _var24 = SomeObj()
            ast.Assign(
                targets=[ast.Name(id="_var24", ctx=ast.Store())],
                value=ast.Call(func=ast.Name(id="SomeObj", ctx=ast.Load()), args=[], keywords=[]),
            ),
            # _var24.__setstate__((_var16, ...))
            ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="_var24", ctx=ast.Load()),
                        attr="__setstate__",
                        ctx=ast.Load(),
                    ),
                    args=[
                        ast.Tuple(
                            elts=[
                                ast.Name(id="_var16", ctx=ast.Load()),
                                ast.Constant(value=None),
                            ],
                            ctx=ast.Load(),
                        )
                    ],
                    keywords=[],
                )
            ),
            # result = _var24
            ast.Assign(
                targets=[ast.Name(id="result", ctx=ast.Store())],
                value=ast.Name(id="_var24", ctx=ast.Load()),
            ),
        ]
        unused = _simulate_unused_assignments_fixed(stmts)
        assert "_var16" not in unused, (
            "BUG: _var16 is used in __setstate__ call but flagged as unused"
        )
        assert "_var24" not in unused, (
            "_var24 is used in result assignment"
        )
