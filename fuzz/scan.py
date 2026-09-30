"""What the harness asserts about fickling, and what counts as a finding.

Pure static analysis throughout: parse, analyse, re-serialize, never deserialize.

A finding is any exception outside `EXPECTED_EXCEPTIONS` escaping an oracle. Those encode
fickling's documented contract, so anything else reaching a caller is a contract violation
by definition -- callers such as ``fickling.load()`` are not written to survive it.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import signal
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO, StringIO

from fickling.analysis import check_safety
from fickling.exception import ResourceExhaustionError
from fickling.fickle import Pickled, PickleDecodeError, StackedPickle

#: Fickling's documented contract for bad input. `PickleDecodeError` covers
#: `EmptyPickleError` and `InterpretationError`. FICKLING_FUZZ_EXPECTED extends this at
#: runtime, to mute a known finding without editing the file.
EXPECTED_EXCEPTIONS: tuple[type[BaseException], ...] = (
    PickleDecodeError,
    ResourceExhaustionError,
)


class OracleViolationError(AssertionError):
    """An invariant the harness checks itself, as opposed to an exception fickling raised."""


class ScanTimeout(BaseException):
    """Raised when an input exceeds the per-input wall-clock budget.

    `BaseException`, because fickling catches ``Exception`` broadly and a hang must not be
    absorbed into a clean scan.
    """


#: Per-input wall-clock ceiling; exceeding it is itself a finding. libFuzzer's ``-timeout``
#: does not reliably interrupt pure-Python work, so without this one slow pickle stalls the
#: session and ``-max_total_time`` stops meaning anything.
DEFAULT_TIME_LIMIT = float(os.environ.get("FICKLING_FUZZ_TIME_LIMIT", "2.0"))

_CAN_SET_ALARM = hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")


@contextlib.contextmanager
def time_limit(seconds: float):
    """Abort the enclosed block after `seconds` of wall clock.

    SIGALRM, so POSIX main thread only -- which is where libFuzzer runs the target.
    Degrades to no limit elsewhere.
    """
    if seconds <= 0 or not _CAN_SET_ALARM:
        yield
        return

    def _fire(_signum, _frame):
        raise ScanTimeout(f"exceeded the {seconds}s per-input limit")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _muted_names() -> frozenset[str]:
    return frozenset(
        n.strip() for n in os.environ.get("FICKLING_FUZZ_EXPECTED", "").split(",") if n.strip()
    )


def _quiet():
    """Swallow fickling's own stderr diagnostics for one oracle call.

    ``fickle.py`` writes "Warning: malformed pickle file..." directly to stderr; at a few
    hundred execs a second that buries the harness's output. FICKLING_FUZZ_VERBOSE=1 keeps it.
    """
    if os.environ.get("FICKLING_FUZZ_VERBOSE"):
        return contextlib.nullcontext()
    return contextlib.redirect_stderr(StringIO())


# --- oracles ---------------------------------------------------------------------------
# Each takes raw pickle bytes and raises on violation. Ordered cheapest-first; `probe`
# stops at the first one that rejects the input.


def oracle_scan(data: bytes) -> None:
    """Parse every pickle in the stream and analyse each. ``to_dict()`` is asserted too,
    since ``fickling --json`` and programmatic callers depend on it."""
    for pickled in StackedPickle.load(BytesIO(data), fail_on_decode_error=True):
        result = check_safety(pickled)
        if result.severity is None:
            raise OracleViolationError("check_safety returned a result with severity=None")
        result.to_dict()


def oracle_roundtrip(data: bytes) -> None:
    """``dumps()`` must be stable under re-parsing.

    Security-relevant, not cosmetic: ``fickling.load()`` analyses the parsed form but
    executes ``dumps()``, so drift means analysis and execution disagree about what the
    pickle is.
    """
    first = Pickled.load(BytesIO(data), fail_on_decode_error=True)
    if first.has_invalid_opcode:
        # The stream carries opcodes fickling could not model, so it makes no promise
        # about reproducing them byte-for-byte.
        return
    once = first.dumps()
    twice = Pickled.load(BytesIO(once), fail_on_decode_error=True).dumps()
    if once != twice:
        raise OracleViolationError(
            f"dumps() is not stable under re-parsing: {len(once)} bytes became {len(twice)}"
        )


def oracle_decompile(data: bytes) -> None:
    """The decompiler must not fall over on anything that parsed."""
    pickled = Pickled.load(BytesIO(data), fail_on_decode_error=True)
    str(pickled.ast)


ORACLES: tuple[tuple[str, Callable[[bytes], None]], ...] = (
    ("scan", oracle_scan),
    ("roundtrip", oracle_roundtrip),
    ("decompile", oracle_decompile),
)


# --- running them ----------------------------------------------------------------------


@dataclass(frozen=True)
class Failure:
    """A single oracle failure, with a signature stable enough to minimize against."""

    oracle: str
    exc: BaseException
    signature: str
    traceback: str

    def __str__(self) -> str:
        return f"[{self.oracle}] {type(self.exc).__name__}: {self.exc}"


_FICKLING_FRAME = re.compile(r"[/\\]fickling[/\\]([\w.]+\.py)$")
_QUOTED = re.compile(r"""(['"]).*?\1""")
#: Must be erased before digits: an address is not a digit run, so digit-stripping alone
#: leaves it varying, and fickling's messages embed object reprs freely.
_ADDRESS = re.compile(r"0x[0-9a-fA-F]+")
_DIGITS = re.compile(r"\d+")
_UNSAFE_IN_PATH = re.compile(r"[^A-Za-z0-9._-]")


def normalize_message(message: str) -> str:
    """Reduce an exception message to the part that identifies the *bug*, not the input.

    Two competing needs. Distinct bugs must not collapse: FLOAT and BYTEARRAY8 both raise
    from the same line of ``Opcode.__new__``, so only the message separates them. But the
    same bug must not fragment: fickling interpolates the offending opcode's repr, so raw
    messages carry addresses and offsets that differ on every input.

    Erasing quoted fragments, addresses and numbers keeps what names the bug -- the opcode
    class, the failed expectation, the AST node type.
    """
    collapsed = _QUOTED.sub("'?'", message)
    collapsed = _ADDRESS.sub("0x?", collapsed)
    collapsed = _DIGITS.sub("#", collapsed)
    return " ".join(collapsed.split())[:120]


def signature(exc: BaseException, oracle: str = "") -> str:
    """Identify *which bug* this is, so minimization cannot silently drift to another one.

    Keyed on the deepest frame inside fickling plus a digest of the normalized message.
    Stable within a run but not across edits, which is the right scope -- it only compares
    candidates during one minimization. Safe as a directory name.

    Excludes the oracle deliberately: the oracles overlap, so shrinking often makes the same
    bug surface through an earlier one, and keying on it would reject those candidates as a
    different bug and block minimization outright.
    """
    if isinstance(exc, ScanTimeout):
        # A timeout fires at an arbitrary point, so the frame says where the clock ran out,
        # not where the cost is. Collapse every hang in one oracle into one finding.
        return f"Timeout-{oracle or 'unknown'}"

    site = "unknown"
    for frame in reversed(traceback.extract_tb(exc.__traceback__)):
        match = _FICKLING_FRAME.search(frame.filename)
        if match:
            site = f"{match.group(1)}:{frame.lineno}"
            break
    digest = hashlib.blake2b(
        normalize_message(str(exc)).encode("utf-8", "replace"), digest_size=4
    ).hexdigest()
    return _UNSAFE_IN_PATH.sub("_", f"{type(exc).__name__}-{site}-{digest}")


def probe(data: bytes, oracles=ORACLES, time_limit_seconds: float | None = None) -> Failure | None:
    """Run the oracles over `data`. Return the first `Failure`, or None if it behaved.

    Returns rather than raises so the minimizer can compare thousands of candidates
    without exception-handling gymnastics.
    """
    muted = _muted_names()
    limit = DEFAULT_TIME_LIMIT if time_limit_seconds is None else time_limit_seconds
    for name, fn in oracles:
        try:
            with time_limit(limit), _quiet():
                fn(data)
        except EXPECTED_EXCEPTIONS:
            # Not a valid pickle, or a deliberate limit. Later oracles would only re-derive
            # the same rejection.
            return None
        except KeyboardInterrupt, SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 - triaging arbitrary failures is the job
            if type(exc).__name__ in muted or any(c.__name__ in muted for c in type(exc).__mro__):
                return None
            return Failure(
                oracle=name,
                exc=exc,
                signature=signature(exc, name),
                traceback="".join(traceback.format_exception(exc)),
            )
    return None
