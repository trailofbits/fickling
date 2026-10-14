"""Regenerate fickling/stdlib.py from real CPython interpreters.

Usage:
    python scripts/generate_stdlib_table.py

Requires one interpreter per supported version. With uv:
    uv python install 3.10 3.11 3.12 3.13 3.14

The script reads sys.stdlib_module_names from each interpreter and rewrites
fickling/stdlib.py with per-version tables plus their union. Run this whenever
fickling gains or drops a supported Python version.
"""

import json
import subprocess
import sys
from pathlib import Path

VERSIONS = ["3.10", "3.11", "3.12", "3.13", "3.14"]

MODULE_PREAMBLE = '''\
"""Versioned CPython standard-library module tables.

This module is GENERATED -- do not edit by hand. Regenerate with:
    python scripts/generate_stdlib_table.py

Each table is the exact contents of ``sys.stdlib_module_names`` captured
from a real CPython interpreter of that version (uv-published builds, the
same source the project's CI matrix installs; top-level module names
only, matching how fickling consumes them). Tables may contain a small
number of platform-specific modules from the build they were captured
with; the union treats them as stdlib everywhere, which only errs toward
flagging private-module imports (the fail-closed direction).

``STDLIB_MODULE_NAMES`` is the union across all supported versions. It is
the default used by the stdlib-membership checks so that scan results do
not depend on which interpreter happens to run the scanner (see
https://github.com/trailofbits/fickling/issues/311).

Default and risks
-----------------
* Default: the union. A module that is stdlib in *any* supported version
  counts as stdlib. This deliberately over-approximates: a pickle is never
  flagged merely because the *scanning* interpreter is older or newer than
  the interpreter the pickle targets.
* Risk: a module removed from the stdlib (e.g. ``imp``, ``pipes``) keeps
  counting as stdlib. If a PyPI package reuses such a name, imports of it
  will look like stdlib imports to ``non_standard_imports``. This does NOT
  weaken the safety verdict: ``UNSAFE_IMPORTS`` is a version-independent
  blocklist and remains the primary control, and private/dunder detection
  is fail-closed under the union (a private module from *any* version is
  flagged).
* To scan against one specific version instead, use
  ``fickling.fickle.set_stdlib_module_names`` with
  ``STDLIB_MODULE_NAMES_BY_VERSION["<major>.<minor>"]`` (or the
  ``--target-python-version`` CLI flag), and
  ``fickling.fickle.reset_stdlib_module_names`` to restore the default.
"""
'''


def capture(version: str) -> list[str]:
    try:
        proc = subprocess.run(
            [
                f"python{version}",
                "-c",
                "import sys, json; print(json.dumps(sorted(sys.stdlib_module_names)))",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise SystemExit(f"could not read stdlib list from python{version}: {e}") from e
    return json.loads(proc.stdout)


def fmt_frozenset(names: list[str], indent: int, prefix: str = "") -> str:
    # Emits Black/ruff-format-clean code: frozenset( on its own line, then the
    # set literal indented one level deeper.
    pad = " " * indent
    entries = ",\n".join(f'{pad}        "{name}"' for name in names)
    return f"{prefix}frozenset(\n{pad}    {{\n{entries},\n{pad}    }}\n{pad})"


def main() -> None:
    tables = {version: capture(version) for version in VERSIONS}
    union = sorted(set().union(*tables.values()))

    out = [MODULE_PREAMBLE]
    out.append("\nSTDLIB_MODULE_NAMES_BY_VERSION: dict[str, frozenset[str]] = {\n")
    out.extend(
        fmt_frozenset(tables[version], 4, prefix=f'    "{version}": ') + ",\n"
        for version in VERSIONS
    )
    out.append("}")
    out.append("\n\nSTDLIB_MODULE_NAMES: frozenset[str] = ")
    out.append(fmt_frozenset(union, 0))
    out.append("\n")

    target = Path(__file__).resolve().parent.parent / "fickling" / "stdlib.py"
    target.write_text("".join(out))
    print(f"wrote {target} ({len(union)} names in union)")


if __name__ == "__main__":
    sys.exit(main())
