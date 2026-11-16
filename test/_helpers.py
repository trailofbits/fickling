"""Shared test helpers for fickling test suite."""

from __future__ import annotations

import pickle
from typing import Any

from fickling.analysis import check_safety
from fickling.fickle import Pickled


def make_malicious_pickle(
    module: str, func: str, args: tuple[Any, ...] = (), protocol: int = 4
) -> bytes:
    """Create a malicious pickle that calls module.func(*args).

    Uses __reduce__ to serialize a payload that, when unpickled, would call
    the specified function. Note: Python resolves the module at pickle time
    via importlib, so dotted module paths like "os.path" resolve to their
    actual implementation (e.g., posixpath on Unix).
    """

    class Payload:
        def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
            import importlib

            mod = importlib.import_module(module)
            fn = getattr(mod, func)
            return (fn, args)

    return pickle.dumps(Payload(), protocol=protocol)


def make_benign_pickle(data: Any | None = None, protocol: int = 4) -> bytes:
    """Create a benign pickle with safe data."""
    if data is None:
        data = [1, 2, 3]
    return pickle.dumps(data, protocol=protocol)


def make_pickle(obj: Any, protocol: int = 4) -> bytes:
    """Create a pickle from a Python object."""
    return pickle.dumps(obj, protocol=protocol)


def assert_not_malicious(data: bytes) -> None:
    """Assert that a pickle is not flagged as overtly malicious.

    Standard library imports may be flagged as SUSPICIOUS (unused variable)
    or LIKELY_UNSAFE (non-standard imports) but should NEVER be flagged as
    OVERTLY_MALICIOUS unless they're actually dangerous.
    """
    from fickling.analysis import Severity

    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity < Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Safe object incorrectly flagged as malicious. "
        f"Severity: {result.severity.name}. Results: {result.to_string()}"
    )


def assert_likely_safe(data: bytes) -> None:
    """Assert that a pickle is LIKELY_SAFE (pure data, no imports)."""
    from fickling.analysis import Severity

    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity == Severity.LIKELY_SAFE, (
        f"Expected LIKELY_SAFE, got {result.severity.name}. Results: {result.to_string()}"
    )
