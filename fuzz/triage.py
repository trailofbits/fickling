"""Turn a crashing pickle into a minimal, filable reproducer.

Minimization is delta debugging over the pickle: whole opcodes first, then individual
bytes. A candidate is kept only if it reproduces the *same* signature, which matters
because almost any truncation of a pickle produces *some* error.

Emits per signature a directory with the original and minimized pickles, a standalone
``repro.py``, and a report carrying the disassembly and an opcode-API skeleton for
``test/test_bypasses.py``.
"""

from __future__ import annotations

import pickletools
import time
from io import StringIO
from pathlib import Path

from fickling.fickle import OPCODES_BY_NAME
from scan import DEFAULT_TIME_LIMIT, Failure, ScanTimeout, probe

#: Byte-level ddmin is O(n^2)-ish in checks, so above this size the opcode pass alone has
#: to do, rather than stalling the fuzzer.
BYTE_PASS_MAX = 2048


def _opcode_units(data: bytes) -> list[bytes] | None:
    """Split `data` on opcode boundaries, or None if it is not disassemblable at all.

    A partial disassembly is fine: the opcodes that did parse are still the right units.
    """
    starts: list[int] = []
    try:
        for _op, _arg, pos in pickletools.genops(data):
            starts.append(pos)
    except Exception:  # noqa: BLE001 - a partial disassembly is still useful
        pass
    if len(starts) < 2:
        return None
    # Each opcode runs from its own start to the next one; the last runs to end-of-input.
    ends = [*starts[1:], len(data)]
    return [data[a:b] for a, b in zip(starts, ends, strict=True)]


def _ddmin(units: list[bytes], still_fails, budget) -> list[bytes]:
    """Classic ddmin: shrink `units` while `still_fails(b"".join(units))` holds."""
    n = 2
    while len(units) >= 2:
        size = max(1, len(units) // n)
        chunks = [units[i : i + size] for i in range(0, len(units), size)]
        for i in range(len(chunks)):
            if not budget():
                return units
            candidate = [u for j, c in enumerate(chunks) if j != i for u in c]
            if candidate and still_fails(b"".join(candidate)):
                units = candidate
                n = max(n - 1, 2)
                break
        else:
            if n >= len(units):
                break
            n = min(n * 2, len(units))
    return units


def minimize(
    data: bytes,
    failure: Failure,
    *,
    max_checks: int = 1500,
    time_budget: float = 5.0,
) -> bytes:
    """Shrink `data` while it keeps reproducing `failure`'s signature.

    Bounded by check count and wall clock, returning the best candidate so far: this runs
    inline in the fuzz loop, on top of libFuzzer's ``-max_total_time``.
    """
    deadline = time.monotonic() + time_budget
    checks = 0

    def budget() -> bool:
        return checks < max_checks and time.monotonic() < deadline

    def still_fails(candidate: bytes) -> bool:
        nonlocal checks
        checks += 1
        found = probe(candidate)
        return found is not None and found.signature == failure.signature

    best = data
    units = _opcode_units(best)
    if units:
        best = b"".join(_ddmin(units, still_fails, budget))

    if len(best) <= BYTE_PASS_MAX and budget():
        best = b"".join(_ddmin([best[i : i + 1] for i in range(len(best))], still_fails, budget))

    return best


# --- reproducer artifacts --------------------------------------------------------------

#: Built through a factory rather than the plain constructor; `pickletools` decodes their
#: argument as "module attr".
_PAIR_FACTORIES = {"GLOBAL", "INST"}


def opcode_api_snippet(data: bytes) -> tuple[str, bool]:
    """Render `data` as fickling-opcode-API calls, plus whether that rendering was verified.

    ``CLAUDE.md`` requires regression tests to build payloads through the opcode API, so
    this does the transcription that would otherwise be done by hand. Verified by rebuilding
    and comparing bytes, never presented as equivalent on faith.
    """
    lines: list[str] = []
    rebuilt: list[object] = []
    exact = True

    try:
        ops = list(pickletools.genops(data))
    except Exception as exc:  # noqa: BLE001
        return f"# not disassemblable: {type(exc).__name__}: {exc}", False

    for op, arg, _pos in ops:
        cls = OPCODES_BY_NAME.get(op.name)
        if cls is None:
            lines.append(f"    # no fickling Opcode class for {op.name} (arg={arg!r})")
            exact = False
            continue
        if op.name == "PROTO":
            lines.append(f"    op.Proto.create({arg!r}),")
            rebuilt.append(cls.create(arg))
        elif op.name in _PAIR_FACTORIES:
            module, _, attr = str(arg).partition(" ")
            lines.append(f"    op.{cls.__name__}.create({module!r}, {attr!r}),")
            rebuilt.append(cls.create(module, attr))
        elif arg is None:
            lines.append(f"    op.{cls.__name__}(),")
            rebuilt.append(cls())
        else:
            lines.append(f"    op.{cls.__name__}({arg!r}),")
            rebuilt.append(cls(arg))

    if exact:
        try:
            from fickling.fickle import Pickled

            exact = Pickled(rebuilt).dumps() == data
        except Exception:  # noqa: BLE001
            exact = False

    body = "\n".join(lines)
    return f"pickled = Pickled(\n    [\n{body}\n    ]\n)", exact


_REPRO_TEMPLATE = '''#!/usr/bin/env python3
"""Standalone reproducer for {signature}.

Exercises the {oracle} path. Scans only -- this never deserializes the pickle.
Run:  python repro.py
"""

from io import BytesIO

{imports}

PICKLE = {payload}


def main() -> None:
{body}

if __name__ == "__main__":
    main()
'''

#: One body per oracle: the reproducer has to drive the *same* path the finding came from.
#: A single fixed body would ship reproducers that exit cleanly for two of the three.
_REPRO_BODIES = {
    "scan": (
        "from fickling.analysis import check_safety\nfrom fickling.fickle import StackedPickle",
        "    for pickled in StackedPickle.load(BytesIO(PICKLE), fail_on_decode_error=True):\n"
        "        check_safety(pickled)\n",
    ),
    "roundtrip": (
        "from fickling.fickle import Pickled",
        "    first = Pickled.load(BytesIO(PICKLE), fail_on_decode_error=True)\n"
        "    once = first.dumps()\n"
        "    twice = Pickled.load(BytesIO(once), fail_on_decode_error=True).dumps()\n"
        "    if once != twice:\n"
        '        raise AssertionError(f"dumps() not stable: {len(once)} -> {len(twice)}")\n',
    ),
    "decompile": (
        "from fickling.fickle import Pickled",
        "    pickled = Pickled.load(BytesIO(PICKLE), fail_on_decode_error=True)\n"
        "    str(pickled.ast)\n",
    ),
}


def render_repro(
    payload: bytes, signature: str, oracle: str, timeout_limit: float | None = None
) -> str:
    """Render a standalone reproducer driving `oracle` over `payload`.

    For a hang the body alone is not a reproducer -- it completes, just slowly, so the script
    would exit 0. `timeout_limit` wraps it in a timing assertion so slowness is what fails.
    """
    imports, body = _REPRO_BODIES[oracle]
    if timeout_limit is not None:
        imports = f"import time\n\n{imports}"
        body = (
            f"    limit = {timeout_limit!r}\n"
            "    started = time.monotonic()\n"
            f"{body}"
            "    elapsed = time.monotonic() - started\n"
            "    if elapsed <= limit:\n"
            '        raise SystemExit(f"completed in {elapsed:.2f}s, under the {limit}s limit")\n'
            '    raise AssertionError(f"scanning took {elapsed:.2f}s (limit {limit}s)")\n'
        )
    return _REPRO_TEMPLATE.format(
        signature=signature,
        oracle=oracle,
        imports=imports,
        payload=repr(payload),
        body=body,
    )


def _disassemble(data: bytes) -> str:
    out = StringIO()
    try:
        pickletools.dis(data, out=out)
    except Exception as exc:  # noqa: BLE001 - a truncated disassembly is still informative
        return f"{out.getvalue()}\n<dis stopped: {type(exc).__name__}: {exc}>"
    return out.getvalue()


def emit(outdir: Path, original: bytes, minimal: bytes, failure: Failure) -> Path | None:
    """Write the artifact set for `failure`. Returns the directory, or None if already known.

    Deduplicates by signature so libFuzzer replaying a crash, or the same bug arriving from
    a hundred different inputs, does not churn the directory.
    """
    target = outdir / failure.signature
    if target.exists():
        return None
    target.mkdir(parents=True, exist_ok=True)

    (target / "original.pkl").write_bytes(original)
    (target / "minimal.pkl").write_bytes(minimal)

    # Re-probe rather than trust the original oracle: signatures exclude the oracle, so a
    # shrunken input can surface the same bug through an earlier path.
    reprobed = probe(minimal)
    oracle = reprobed.oracle if reprobed is not None else failure.oracle
    is_hang = isinstance((reprobed or failure).exc, ScanTimeout)
    (target / "repro.py").write_text(
        render_repro(
            minimal,
            failure.signature,
            oracle,
            timeout_limit=DEFAULT_TIME_LIMIT if is_hang else None,
        )
    )

    snippet, exact = opcode_api_snippet(minimal)
    verified = (
        "verified: rebuilding through these opcodes reproduces minimal.pkl byte-for-byte"
        if exact
        else "APPROXIMATE: does not rebuild minimal.pkl exactly; check before using"
    )
    (target / "report.md").write_text(
        f"""# {failure.signature}

    oracle:     {oracle}{"" if oracle == failure.oracle else f" (first seen via {failure.oracle})"}
    exception:  {type(failure.exc).__name__}: {failure.exc}
    original:   {len(original)} bytes
    minimized:  {len(minimal)} bytes

## Reproduce

```
python {target / "repro.py"}
```

## Traceback

```
{failure.traceback.rstrip()}
```

## Minimized pickle

```
{_disassemble(minimal).rstrip()}
```

## As a regression test

`test/test_bypasses.py` builds payloads through the opcode API. Skeleton ({verified}):

```python
{snippet}
```
"""
    )
    return target
