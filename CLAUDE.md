# Fickling

Static analyzer, decompiler, and bytecode rewriter for Python pickle serializations. Detects malicious pickle files including PyTorch models. Maintained by Trail of Bits.

## Commands

```bash
make dev            # uv sync --all-extras
make test           # pytest --cov=fickling test/ + coverage report
make test-quick     # pytest -q test/ (no coverage)
make lint           # ruff format --check + ruff check + mypy
make format         # ruff check --fix + ruff format
```

CI uses `ty check fickling/` for type checking (not mypy). Run `uv run ty check fickling/` locally to match CI.

## Architecture

```
fickling/
  fickle.py      # Core: pickle AST, opcode classes, interpreter, UNSAFE_IMPORTS blocklist
  analysis.py    # Security analysis framework: Analysis base class, Severity enum, check_safety()
  ml.py          # ML-specific safety: UnsafeImportsML, MLAllowlist with UNSAFE_MODULES dict
  polyglot.py    # Multi-format: TAR, ZIP, 7z, NumPy NPZ archive scanning
  pytorch.py     # PyTorch model injection via BaseInjection
  loader.py      # Public API: fickling.load() / fickling.loads() with safety checks
  hook.py        # Runtime protection: activate_safe_ml_environment()
  cli.py         # CLI argument parsing and output (all print/stdout goes here, not in library code)
  constants.py   # ClamAV-compatible exit codes (EXIT_CLEAN=0, EXIT_UNSAFE=1, EXIT_ERROR=2)
  exception.py   # Custom exceptions: WrongMethodError, InterpretationError, PickleDecodeError
```

### Key design rules

- **`check_safety()` is the primary API.** It returns an `AnalysisResult` with a `severity` field. Library code returns data; CLI code prints it.
- **No stdout/stderr in library code.** Print statements, result formatting, and JSON output belong in `cli.py` only. If someone uses fickling programmatically, they get structured results, not console noise.
- **Two parallel blocklists exist.** `UNSAFE_IMPORTS` in `fickle.py` (general) and `UNSAFE_MODULES`/`UNSAFE_IMPORTS` in `analysis.py` (ML-specific with descriptions). Both must be updated when adding dangerous modules.
- **`fickling.load()` re-serializes before loading.** It calls `pickle.loads(pickled_data.dumps())` rather than `pickle.load(file)` to prevent TOCTOU race conditions where the file changes between analysis and load.
- **Graceful degradation for optional deps.** Features gated on optional dependencies (torch, py7zr) must work when the dependency is missing. Check availability at import time, not at call time.

## Testing

All tests use `unittest.TestCase`. Test files are in `test/`.

```bash
uv run pytest -q test/                     # all tests
uv run pytest -q test/test_bypasses.py     # just bypass regression tests
```

### Test patterns

**Bypass/vulnerability tests** build pickles using the opcode API and assert severity:

```python
def test_example_bypass(self):
    pickled = Pickled([
        op.Proto.create(4),
        op.ShortBinUnicode("dangerous_module"),
        op.ShortBinUnicode("dangerous_func"),
        op.StackGlobal(),
        op.EmptyTuple(),
        op.Reduce(),
        op.Stop(),
    ])
    self.assertGreater(check_safety(pickled).severity, Severity.LIKELY_SAFE)
```

Build payloads using fickling's opcode API (`op.Proto`, `op.ShortBinUnicode`, `op.StackGlobal`, `op.Reduce`, etc.) or Python's `pickle` module. Do not submit raw bytes or hand-assembled byte strings.

### Test organization

| File | Purpose |
|------|---------|
| `test_bypasses.py` | Regression tests for CVEs and GHSAs (each links to advisory) |
| `test_attack_vectors.py` | Malicious payload detection |
| `test_benign_edge_cases.py` | Safe pickle variants (false positive prevention) |
| `test_cve_patterns.py` | CVE pattern detection |
| `test_archive_scanning.py` | Archive/polyglot format tests |
| `test_crashes.py` | Malformed input handling |
| `test_pickle.py` | Core pickle module tests |
| `test_hook.py` | Hook functionality |

## Code style

- **Formatter/linter:** ruff (line-length 100, double quotes, target py310)
- **Type checker:** ty (CI runs with `continue-on-error` — 55 remaining errors being addressed incrementally)
- **Imports:** `import fickling.fickle as op` is the convention for opcode access in tests
- **AST visitor methods** in `fickle.py` use `visit_*` naming (suppresses N802)
- **Error handling:** Malformed pickles raise `InterpretationError` (subclass of `PickleDecodeError`), not `ValueError`. The `has_interpretation_error` flag on `Pickled` signals downstream analysis to report `LIKELY_UNSAFE`.
- **Exception design:** Exception messages are constructor arguments, not hardcoded in the class.
- **Functions return data, not print.** Separation between computation and presentation is strict.

## CI

| Workflow | What it checks |
|----------|---------------|
| `tests.yml` | pytest across Python 3.10-3.14 |
| `lint.yml` | ruff format + ruff check + ty check |
| `pip-audit.yml` | Dependency vulnerability scan (runs daily + on PRs) |
| `release.yml` | PyPI publishing on tags |

Actions are SHA-pinned with version comments. uv is used for dependency caching.

## Vulnerability reporting

### Include a minimal reproducing test case

Every report must include a test case for `test/test_bypasses.py` following the existing pattern. Link the GHSA/CVE in a comment above the test method.

### Use non-offensive payloads

Use `echo` or `print` to demonstrate code execution. Do not spawn shells, read sensitive files, or execute remote scripts.

### Keep the impact section minimal

Do not write elaborate exploitation scenarios. A brief explanation is sufficient — e.g., "module X is not in the unsafe imports list and can be used for code execution."

### Update both blocklists

When adding dangerous modules, update `UNSAFE_IMPORTS` in `fickle.py` **and** the relevant dict in `analysis.py` (`UNSAFE_MODULES` or `UNSAFE_IMPORTS`). Match only specific dangerous names (e.g., `_io.FileIO` not all of `_io`) to avoid false positives.

### Match all components of dotted module paths

Import matching checks all components of the module path: `any(component in UNSAFE_IMPORTS for component in module.split("."))`. This prevents bypasses via re-exports like `foo.bar.os`.

### Out of scope: UnusedVariables heuristic

We are **not** interested in bypasses of the `UnusedVariables` analysis. This is an intentionally weak, supplementary heuristic. Bypassing it alone is not a meaningful finding.

### No suggested fixes without human review

Do not include suggested code fixes unless they have been reviewed and approved by a human operator first.
