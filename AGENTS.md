# Fickling

Static analyzer, decompiler, and bytecode rewriter for Python pickle serializations. Detects malicious pickle files including PyTorch models. Maintained by Trail of Bits.

## Commands

```bash
make dev            # uv sync --all-extras
make test           # pytest --cov=fickling test/ + coverage report
make test-quick     # pytest -q test/ (no coverage)
make lint           # ruff format --check + ruff check + ty (advisory)
make format         # ruff check --fix + ruff format
```

`make lint` mirrors `lint.yml`: formatting is checked over the whole repo
(including Python snippets in Markdown), and `ty` is advisory, so a non-zero
`ty` exit does not fail the target. Use `make typecheck` to have it fail.

## Architecture

```
fickling/
  fickle.py      # Core: pickle AST, opcode classes, interpreter, UNSAFE_IMPORTS blocklist
  analysis.py    # Security analyses, including UnsafeImportsML; check_safety()
  ml.py          # ML import allowlist and protected unpickler
  polyglot.py    # Multi-format: TAR, ZIP, 7z, NumPy NPZ archive scanning
  pytorch.py     # PyTorch model injection via BaseInjection
  loader.py      # Public API: fickling.load() / fickling.loads() with safety checks
  hook.py        # Runtime protection: activate_safe_ml_environment()
  cli.py         # CLI argument parsing and output (all print/stdout goes here, not in library code)
  constants.py   # ClamAV-compatible exit codes (EXIT_CLEAN=0, EXIT_UNSAFE=1, EXIT_ERROR=2)
  exception.py   # Custom exceptions: WrongMethodError, InterpretationError, PickleDecodeError
```

When in doubt about the behavior of a pickle opcode, cross-check fickling's implementation against CPython's upstream sources:
- https://github.com/python/cpython/blob/main/Lib/pickle.py (pure-Python implementation)
- https://github.com/python/cpython/blob/main/Modules/_pickle.c (C-accelerated implementation, used by default)
- https://github.com/python/cpython/blob/main/Lib/pickletools.py (opcode definitions and documentation)

Flag to the operator any obvious bugs in the upstream CPython parser or behavioral differentials between the pure-Python and C-accelerated implementations.

### Key design rules

- **`check_safety()` is the primary analysis API.** It returns `AnalysisResults`, which has a `severity` field. Library code returns data; CLI code presents it.
- **No stdout/stderr in library code.** Print statements, result formatting, and JSON output belong in `cli.py` only. If someone uses fickling programmatically, they get structured results, not console noise.
- **Two parallel blocklists exist.** `UNSAFE_IMPORTS` in `fickle.py` (general) and `UNSAFE_MODULES`/`UNSAFE_IMPORTS` in `analysis.py` (ML-specific with descriptions). Update the one that matches the kind of module being added: ML-specific libraries go in `analysis.py`, generic dangerous modules go in `fickle.py`.
- **`fickling.load()` re-serializes before loading.** It calls `pickle.loads(pickled_data.dumps())` rather than `pickle.load(file)` to prevent TOCTOU race conditions where the file changes between analysis and load.
- **Graceful degradation for optional deps.** Features gated on optional dependencies (torch, py7zr) must handle their absence.

## Testing

All tests use `unittest.TestCase`. Test files are in `test/`.

```bash
uv run pytest -q test/                     # all tests
uv run pytest -q test/test_bypasses.py     # just bypass regression tests
```

### Test organization

| File | Purpose |
|------|---------|
| `test_bypasses.py` | Regression tests for security bypasses |
| `test_analysis.py` | Safety analysis, including benign pickle variants |
| `test_polyglot.py` | Archive and polyglot format tests |
| `test_crashes.py` | Malformed input handling |
| `test_pickle.py` | Core pickle module tests |
| `test_hook.py` | Hook functionality |
| `test_pytorch.py` | PyTorch model handling |

## Code style

- **Formatter/linter:** ruff (line-length 100, double quotes, target py311)
- **Type checker:** ty (target Python 3.11; CI runs with `continue-on-error`)
- **Imports:** `import fickling.fickle as op` is the convention for opcode access in tests
- **AST visitor methods** in `fickle.py` use `visit_*` naming (suppresses N802)
- **Error handling:** Malformed pickles raise `InterpretationError` (subclass of `PickleDecodeError`), not `ValueError`. The `has_interpretation_error` flag on `Pickled` signals downstream analysis to report `LIKELY_UNSAFE`.
- **Exception design:** Exception messages are constructor arguments, not hardcoded in the class.

## CI

| Workflow | What it checks |
|----------|---------------|
| `tests.yml` | pytest across Python 3.11-3.15 |
| `lint.yml` | ruff format + ruff check + ty check |
| `pip-audit.yml` | Dependency vulnerability scan (runs daily + on PRs) |
| `release.yml` | PyPI publishing on tags |

## Vulnerability fixes

See `SECURITY.md` for reporting policy. When implementing fixes:

- Add a regression test when it checks a distinct failure mode. Do not add one test per report just to restate a blocklist entry.
- Update the appropriate blocklist: `UNSAFE_IMPORTS` in `fickle.py` for generic dangerous modules, or the relevant dict in `analysis.py` for ML-specific libraries. Match specific names whenever possible (e.g., `_io.FileIO` not all of `_io`) to avoid false positives.
- Import matching checks all components of dotted paths (`foo.bar.os` matches `os`).
