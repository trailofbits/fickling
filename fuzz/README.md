# Fuzzing fickling's scanner

A coverage-guided fuzzing harness for fickling's static analysis, pairing
[atheris](https://github.com/google/atheris) with
[cisco-ai-defense/pickle-fuzzer](https://github.com/cisco-ai-defense/pickle-fuzzer).

Atheris supplies coverage feedback over instrumented Python; the pickle generator is a Rust
extension that emits structurally valid pickles. Without the generator, a byte-level fuzzer
spends nearly all its time on inputs fickling rejects in the first opcode. Without atheris,
the generator has nothing telling it which pickles reached new code.

**Manual only.** Nothing here runs in CI, and this is a separate uv project with its own
lockfile and interpreter, so none of it reaches the published package or `make dev`.

**Scanning only.** The harness never deserializes a pickle: every oracle parses, analyses
and re-serializes, and the emitted reproducers do the same.

## Setup

Both dependencies are built from source, because neither ships a wheel that is usable here:
the generator is a maturin/PyO3 extension not published to PyPI at all, and atheris publishes
manylinux x86_64 wheels only -- so macOS and aarch64 always compile it, and the 3.1.0 release
that supports Python 3.14 has no sdist, meaning PyPI cannot serve it off x86_64 at all. Hence
clang, cargo, and the Python dev headers:

```bash
sudo apt install clang llvm python3-dev   # or: brew install llvm python
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

make env                     # uv sync -> fuzz/.venv, builds both deps
make check                   # self-test: no fuzzing, ~1s
```

The dev headers are easy to miss: without them the build fails deep in a compiler log with
`fatal error: 'Python.h' file not found`. uv-managed interpreters already have them, and uv
fetches one itself, so this only bites against a system Python.

**Python 3.14 only, by design.** Atheris rewrites bytecode for coverage and hard-gates on the
versions it knows, and both dependencies are unreleased source builds. Pinning one
interpreter keeps that combination reproducible instead of resolving differently per host.
Nothing is lost: findings concern fickling's pickle parsing, which is not version-specific.

## Its own uv project

`fuzz/pyproject.toml` is a standalone project -- not a workspace member -- with its own
`fuzz/uv.lock` and its own `.venv`. A uv workspace shares one lockfile and one virtualenv,
and neither works here: syncing a 3.14-pinned fuzzer into a shared venv would clobber the
dev environment, and a shared lock would put a git-pinned atheris in front of everyone who
resolves fickling.

The root `pyproject.toml` does not reference `fuzz/` at all; `uv lock` at the root resolves
72 packages with no trace of atheris. The dependency on fickling goes the other way, as an
editable path dependency on `..`, so the harness always fuzzes the working tree.

Two consequences worth knowing:

- Both git dependencies are pinned to an immutable rev. The generator uses its `v1.0.1` tag.
  Atheris has no usable tag -- upstream's newest is `3.0.0`, which predates 3.13/3.14 support,
  and the 3.1.0 that works here is untagged `main` -- so it is pinned to a commit SHA instead.
  Worth revisiting if upstream ever tags 3.1.0.
- `/fuzz` is in the sdist `exclude` list. Without it hatchling ships the whole directory,
  corpus included, in every published release.

Upstream's generator still declares `requires-python = ">=3.11,<3.12"`. That is stale
metadata rather than a real limit: it is a pyo3 0.29 extension and builds and runs fine on
3.14, verified here.

## Running

Everything below runs from this directory (`cd fuzz`), against `fuzz/Makefile`. Every target
goes through `uv run`, which creates `.venv` from `uv.lock` on first use, so `make env` is
optional -- useful only when you would rather pay for the source builds up front than inside
the first run.

```bash
make help                    # the list below
make fuzz                    # 60s, seeds a corpus on first run
make fuzz ARGS='-max_total_time=3600 -jobs=4'
make report                  # list what previous runs found
make test                    # unit tests for the harness itself
make coverage                # HTML report of what the corpus reaches
make clean                   # drop corpus, findings and coverage output
```

`ARGS` is passed to libFuzzer, so `-max_len`, `-jobs`, `-rss_limit_mb`, `-timeout`, and
friends all work. Useful ones:

| Flag | Why |
|---|---|
| `-max_total_time=N` | Wall-clock budget for fuzzing. Minimization time is *additional*, so a run with many new findings overshoots. |
| `-jobs=N` | Parallel workers. Each gets its own log. |
| `-max_len=N` | Cap pickle size. Larger finds deeper nesting bugs, slower. |

libFuzzer's own `-timeout` is not the hang detector here; it does not reliably interrupt
pure-Python work, and one pathological pickle would otherwise stall the session and make
`-max_total_time` meaningless. The harness enforces its own per-input ceiling instead
(`--time-limit`, default 2s, `FICKLING_FUZZ_TIME_LIMIT` to change it) and reports anything
slower as a finding. Set `--time-limit 0` to disable.

Direct invocation, for the flags the Makefile does not cover. `uv run` picks up this
directory's project and resolves the pinned interpreter, so there is no venv path to
remember:

```bash
uv run python harness.py corpus -max_total_time=300
uv run python harness.py --replay artifacts/*/minimal.pkl
uv run python harness.py --help
```

From elsewhere in the repository, add `--project fuzz` and adjust the paths:
`uv run --project fuzz python fuzz/harness.py fuzz/corpus -max_total_time=300`.

## Coverage

```bash
make coverage                # writes fuzz/htmlcov/index.html
```

Replays every corpus input through the oracles under coverage.py and writes a browsable
HTML report. libFuzzer's own `cov:` counter is an edge count with no source mapping -- it
says coverage went up without saying of what -- so this is how you see which parts of
fickling the corpus actually exercises, and which it never touches.

It runs through `corpus_coverage.py` rather than `harness.py`, and so never imports atheris:
atheris rewrites fickling's bytecode to insert its own counters, and measuring that with
coverage.py reports the rewritten module rather than the source. Same oracles, same
`scan.probe`, no fuzzer around them.

Expect the analysis path to dominate and the rest to sit near zero -- roughly 70% of
`fickle.py` and 80% of `analysis.py`, against 0% for `polyglot.py`, `pytorch.py` and
`tracing.py`. That is the harness working as designed, not a gap in the corpus: the oracles
take raw pickle bytes, so archive scanning, PyTorch model handling and the tracing
interpreter are never entered. Treat those files as out of scope here rather than as
coverage to chase.

## Findings

A run does **not** stop at the first crash. Fickling has a few failure modes reachable
within the first second, so aborting on the first one would mean every session rediscovers
the same bug and nothing else. Instead each distinct finding is reported once, minimized,
and the run continues. Pass `--exit-on-finding` for the usual libFuzzer behaviour.

Each finding gets `fuzz/artifacts/<signature>/`:

| File | Contents |
|---|---|
| `report.md` | Traceback, disassembly of the minimized pickle, and an opcode-API skeleton for `test/test_bypasses.py` |
| `minimal.pkl` | The delta-debugged pickle |
| `original.pkl` | What the fuzzer originally produced |
| `repro.py` | Standalone script that reproduces it, scanning only |

Minimization is delta debugging over the pickle -- whole opcodes first, then individual
bytes. A candidate is kept only if it reproduces the *same* signature, which matters
because almost any truncation of a pickle produces *some* error. In practice a few-hundred
byte input collapses to a handful of bytes.

Signatures are `<exception>-<file>_<line>-<digest>`, where the digest covers the exception
message with numbers, quoted fragments and heap addresses erased. Every part of that is
load-bearing:

- The **line** alone is not enough: `FLOAT` and `BYTEARRAY8` both raise from the same line
  of `Opcode.__new__`, so only the message separates them.
- The **erasure** is not optional: fickling interpolates the offending opcode's `repr` into
  its messages, so the raw message carries a heap address and stream offset that differ on
  every input. Keying on that files a fresh report per input and never converges.
- The **oracle is excluded**: the oracles overlap, since `check_safety` builds the AST the
  decompiler also walks. Shrinking an input often makes the same bug surface through an
  earlier oracle, and keying on the oracle rejects those candidates as "a different bug",
  blocking minimization outright.

Hangs are the exception: they are keyed `Timeout-<oracle>`, because a timeout fires at an
arbitrary line and the frame says where the clock ran out rather than where the cost is.

Re-running does not re-report what is already in `artifacts/`. Delete a directory to have
that finding surface again, and `make report` to list them.

### What counts as a finding

`scan.EXPECTED_EXCEPTIONS` encodes fickling's documented contract: malformed input raises
`PickleDecodeError`, resource limits raise `ResourceExhaustionError`. Anything else
escaping an oracle is a finding, because callers such as `fickling.load()` are not written
to survive it.

Three oracles run per input, cheapest first:

- **`scan`** -- `StackedPickle.load` then `check_safety` on each pickle, plus `to_dict()`,
  which the CLI and any programmatic caller depend on.
- **`roundtrip`** -- `dumps()` must be stable under re-parsing. Security-relevant, not
  cosmetic: `fickling.load()` analyses the parsed form but executes `dumps()` output, so
  drift there means analysis and execution disagree about what the pickle is.
- **`decompile`** -- `str(pickled.ast)` must not fall over on anything that parsed.

To mute a known finding without editing code:

```bash
FICKLING_FUZZ_EXPECTED=NotImplementedError make fuzz
FICKLING_FUZZ_VERBOSE=1 ...          # show fickling's own stderr diagnostics
```

### Findings present on master

A first run rediscovers these immediately. They are pre-existing, unrelated to the harness,
and left alone here:

- `NotImplementedError` from `Opcode.__new__` for the four opcodes with no fickling class:
  `FLOAT`, `BYTEARRAY8`, `NEXT_BUFFER`, `READONLY_BUFFER`. Reaches callers instead of the
  documented `PickleDecodeError`.
- `AttributeError`, `IndexError` and `ValueError` out of `check_safety` and the decompiler on
  malformed streams.
- `Timeout-scan`: inputs where analysis runs for seconds. Fickling has resource limits but no
  wall clock, so the ceiling that catches these is the harness's.

Two unrelated things also worth knowing, since both show up the moment you build the env:

- `fickling/fickle.py` imports `typing_extensions.Buffer` below Python 3.12, but
  `typing-extensions` is declared only in the `lint` extra rather than in
  `[project] dependencies`, so `pip install fickling` is not importable on 3.10 or 3.11.
  Pinning this project to 3.14 sidesteps it; the bug is still there for anyone else.
- Six sites in `fickle.py` write `Warning: malformed pickle file...` straight to
  `sys.stderr`, which `CLAUDE.md` reserves for `cli.py`. At a few hundred executions a second
  that buries the harness output, so `scan.py` suppresses it unless
  `FICKLING_FUZZ_VERBOSE=1`.

## Layout

```
fuzz/
  pyproject.toml   the separate uv project: pinned deps, interpreter, ruff overrides
  uv.lock          its own lock; the parent's is untouched
  Makefile         every target, all via `uv run`
  harness.py       atheris entry point, custom mutator, CLI
  scan.py          the oracles, what counts as a finding, signatures
  triage.py        delta debugging and reproducer artifacts
  corpus_coverage.py  corpus replay under coverage.py, atheris deliberately absent
  tests/           unit tests for the above; needs neither atheris nor the generator
```

Modules are imported by path rather than as a package, so `harness.py` is runnable
directly and the tests can import the modules without installing anything.

The generator is wired in as an atheris `custom_mutator` rather than called from inside the
test function. That keeps libFuzzer's corpus in *pickle space*: corpus entries and crash
artifacts are themselves pickles, coverage is attributed to real pickle structure, and
`-minimize_crash=1` works natively. 15% of mutations are plain byte mutations rather than
generated pickles, which is how the harness keeps reaching fickling's malformed-input
paths -- a generator that only emits well-formed pickles would never test them.
