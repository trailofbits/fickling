"""Benign edge case tests for fickling.

These tests verify that fickling correctly identifies safe patterns and prevents
false positives. The key distinction:

- LIKELY_SAFE: Pure data structures with no function calls
- SUSPICIOUS: Safe imports but unused variables (by design - fickling flags this)
- LIKELY_UNSAFE: Non-standard imports or unsafe calls
- OVERTLY_MALICIOUS: Known dangerous operations

Known Limitations (Documented False Positives):
- `builtins` module imports (range, slice, set, frozenset) are flagged as LIKELY_OVERTLY_MALICIOUS
  because builtins contains dangerous functions like eval/exec. This is a conservative approach.
- Protocol 0 uses GLOBAL opcode which may trigger different detection paths.

Key patterns tested:
- Standard library safe imports should NOT be OVERTLY_MALICIOUS (most cases)
- Pure data structures (no imports) should be LIKELY_SAFE
- Custom class serialization
- NumPy arrays and dtypes (optional)
- False positive prevention for strings containing dangerous keywords
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum, IntEnum
from fractions import Fraction
from pathlib import PurePosixPath
from typing import Any, NamedTuple
from uuid import UUID

import pytest

from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled
from test._helpers import assert_likely_safe, assert_not_malicious, make_pickle

# Higher protocols use more modern opcodes with fewer false positives
# Note: Protocol 5 with NumPy can cause parsing issues in fickling
HIGHER_PROTOCOLS = [2, 3, 4, 5]
HIGHER_PROTOCOLS_NUMPY = [2, 3, 4]  # Exclude protocol 5 for NumPy due to out-of-band data
ALL_PROTOCOLS = [0, 1, 2, 3, 4, 5]


# =============================================================================
# Pure Data Structures (No Imports) - Should be LIKELY_SAFE
# Higher protocols (2+) are more likely to produce clean pickles.
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_primitive_types_safe(protocol: int) -> None:
    """Primitive types (int, float, str, bool, None) should be LIKELY_SAFE."""
    for obj in [42, 3.14, "hello", True, False, None]:
        data = make_pickle(obj, protocol)
        assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_list_safe(protocol: int) -> None:
    """Lists should be LIKELY_SAFE."""
    data = make_pickle([1, 2, 3, "a", "b", "c"], protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_dict_safe(protocol: int) -> None:
    """Dicts should be LIKELY_SAFE."""
    data = make_pickle({"key": "value", "num": 42}, protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_tuple_with_many_elements_safe(protocol: int) -> None:
    """Tuples with many elements should be LIKELY_SAFE."""
    data = make_pickle(tuple(range(100)), protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_deeply_nested_list_safe(protocol: int) -> None:
    """Deeply nested lists should be LIKELY_SAFE."""
    nested = [[[[[[1, 2, 3]]]]]]
    data = make_pickle(nested, protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_deeply_nested_dict_safe(protocol: int) -> None:
    """Deeply nested dicts should be LIKELY_SAFE."""
    nested = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    data = make_pickle(nested, protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_large_list_safe(protocol: int) -> None:
    """Large lists should be LIKELY_SAFE."""
    data = make_pickle(list(range(10000)), protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_large_dict_safe(protocol: int) -> None:
    """Large dicts should be LIKELY_SAFE."""
    d = {f"key_{i}": i for i in range(1000)}
    data = make_pickle(d, protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_unicode_strings_safe(protocol: int) -> None:
    """Unicode strings with special characters should be LIKELY_SAFE."""
    data = make_pickle("Hello 世界 🌍 αβγ", protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_empty_containers_safe(protocol: int) -> None:
    """Empty containers should be LIKELY_SAFE."""
    for obj in [[], {}, ()]:
        data = make_pickle(obj, protocol)
        assert_likely_safe(data)


# =============================================================================
# Standard Library Objects - Should NOT be OVERTLY_MALICIOUS
#
# These objects use __reduce__ which creates function calls, so fickling
# correctly marks them as SUSPICIOUS (unused variable). But they should
# NEVER be flagged as OVERTLY_MALICIOUS since they're safe stdlib objects.
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_datetime_not_malicious(protocol: int) -> None:
    """datetime objects should not be flagged as malicious."""
    data = make_pickle(datetime.now(), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_date_not_malicious(protocol: int) -> None:
    """date objects should not be flagged as malicious."""
    data = make_pickle(date.today(), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_time_not_malicious(protocol: int) -> None:
    """time objects should not be flagged as malicious."""
    data = make_pickle(time(12, 30, 45), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_timedelta_not_malicious(protocol: int) -> None:
    """timedelta objects should not be flagged as malicious."""
    data = make_pickle(timedelta(days=1, hours=2), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_timezone_not_malicious(protocol: int) -> None:
    """timezone objects should not be flagged as malicious."""
    data = make_pickle(timezone.utc, protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_uuid_not_malicious(protocol: int) -> None:
    """UUID objects should not be flagged as malicious."""
    data = make_pickle(UUID("12345678-1234-5678-1234-567812345678"), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_decimal_not_malicious(protocol: int) -> None:
    """Decimal objects should not be flagged as malicious."""
    data = make_pickle(Decimal("123.456"), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_fraction_not_malicious(protocol: int) -> None:
    """Fraction objects should not be flagged as malicious."""
    data = make_pickle(Fraction(1, 3), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_pathlib_not_malicious(protocol: int) -> None:
    """PurePath objects should not be flagged as malicious."""
    data = make_pickle(PurePosixPath("/usr/local/bin"), protocol)
    assert_not_malicious(data)


# =============================================================================
# Collections Module - Should NOT be OVERTLY_MALICIOUS
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_ordered_dict_not_malicious(protocol: int) -> None:
    """OrderedDict should not be flagged as malicious."""
    data = make_pickle(OrderedDict([("a", 1), ("b", 2)]), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_counter_not_malicious(protocol: int) -> None:
    """Counter should not be flagged as malicious."""
    data = make_pickle(Counter(["a", "b", "a", "c"]), protocol)
    assert_not_malicious(data)


# =============================================================================
# Custom Class Serialization - Should NOT be OVERTLY_MALICIOUS
# =============================================================================


class SimpleEnum(Enum):
    """Simple enum for testing."""

    VALUE_A = "a"
    VALUE_B = "b"


class SimpleIntEnum(IntEnum):
    """Simple int enum for testing."""

    ONE = 1
    TWO = 2


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_enum_not_malicious(protocol: int) -> None:
    """Enum subclasses should not be flagged as malicious."""
    data = make_pickle(SimpleEnum.VALUE_A, protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_int_enum_not_malicious(protocol: int) -> None:
    """IntEnum subclasses should not be flagged as malicious."""
    data = make_pickle(SimpleIntEnum.ONE, protocol)
    assert_not_malicious(data)


class SimpleNamedTuple(NamedTuple):
    """Simple named tuple for testing."""

    x: int
    y: str
    z: float


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_namedtuple_not_malicious(protocol: int) -> None:
    """NamedTuple instances should not be flagged as malicious."""
    data = make_pickle(SimpleNamedTuple(1, "hello", 3.14), protocol)
    assert_not_malicious(data)


@dataclass
class SimpleDataclass:
    """Simple dataclass for testing."""

    name: str
    value: int
    items: list[int]


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_dataclass_not_malicious(protocol: int) -> None:
    """Simple dataclasses without callables should not be flagged as malicious."""
    data = make_pickle(SimpleDataclass("test", 42, [1, 2, 3]), protocol)
    assert_not_malicious(data)


class CustomGetState:
    """Class with __getstate__/__setstate__ for data only."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __getstate__(self) -> dict[str, Any]:
        return {"value": self.value}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.value = state["value"]


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_custom_getstate_setstate_not_malicious(protocol: int) -> None:
    """Classes with __getstate__/__setstate__ should not be flagged as malicious."""
    data = make_pickle(CustomGetState(42), protocol)
    assert_not_malicious(data)


# =============================================================================
# NumPy Edge Cases (Optional - skip if numpy not installed)
# Should NOT be OVERTLY_MALICIOUS
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS_NUMPY)
def test_numpy_array_not_malicious(protocol: int) -> None:
    """NumPy arrays should not be flagged as malicious."""
    np = pytest.importorskip("numpy")
    arr = np.array([1, 2, 3, 4, 5])
    data = make_pickle(arr, protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS_NUMPY)
def test_numpy_multidimensional_not_malicious(protocol: int) -> None:
    """Multi-dimensional NumPy arrays should not be flagged as malicious."""
    np = pytest.importorskip("numpy")
    arr = np.array([[1, 2, 3], [4, 5, 6]])
    data = make_pickle(arr, protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS_NUMPY)
def test_numpy_scalar_not_malicious(protocol: int) -> None:
    """NumPy scalars (int32, float64) should not be flagged as malicious."""
    np = pytest.importorskip("numpy")
    data = make_pickle(np.int32(42), protocol)
    assert_not_malicious(data)
    data = make_pickle(np.float64(3.14), protocol)
    assert_not_malicious(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS_NUMPY)
def test_numpy_structured_array_not_malicious(protocol: int) -> None:
    """Structured NumPy arrays with named fields should not be flagged as malicious."""
    np = pytest.importorskip("numpy")
    dt = np.dtype([("name", "U10"), ("age", "i4"), ("weight", "f8")])
    arr = np.array([("Alice", 25, 55.0), ("Bob", 30, 75.5)], dtype=dt)
    data = make_pickle(arr, protocol)
    assert_not_malicious(data)


# =============================================================================
# False Positive Prevention - Strings containing dangerous keywords
# These should ALL be LIKELY_SAFE (just strings, no imports)
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_string_containing_exec_safe(protocol: int) -> None:
    """String containing 'exec' should be LIKELY_SAFE."""
    data = make_pickle("You must exec this command manually", protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_string_containing_eval_safe(protocol: int) -> None:
    """String containing 'eval' should be LIKELY_SAFE."""
    data = make_pickle("Please eval the results carefully", protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_string_containing_import_safe(protocol: int) -> None:
    """String containing 'import' should be LIKELY_SAFE."""
    data = make_pickle("import os is dangerous in pickles", protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_string_containing_os_safe(protocol: int) -> None:
    """String containing 'os' should be LIKELY_SAFE."""
    data = make_pickle("macOS and Windows are operating systems", protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_dict_with_suspicious_looking_keys_safe(protocol: int) -> None:
    """Dict with suspicious-looking keys should be LIKELY_SAFE."""
    data = make_pickle(
        {
            "exec": "value",
            "eval": "value",
            "__reduce__": "value",
            "os": "value",
            "subprocess": "value",
        },
        protocol,
    )
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_string_with_code_snippet_safe(protocol: int) -> None:
    """String containing code snippet should be LIKELY_SAFE."""
    code_str = """
    import os
    os.system('rm -rf /')
    eval('malicious')
    exec('code')
    """
    data = make_pickle(code_str, protocol)
    assert_likely_safe(data)


# =============================================================================
# ML Framework Patterns (Optional - skip if dependencies not installed)
# Should NOT be OVERTLY_MALICIOUS
# =============================================================================


def test_sklearn_model_not_malicious() -> None:
    """Scikit-learn model serialization should not be flagged as malicious."""
    np = pytest.importorskip("numpy")
    sklearn_lm = pytest.importorskip("sklearn.linear_model")
    model = sklearn_lm.LinearRegression()
    x_train = np.array([[1], [2], [3]])
    y_train = np.array([1, 2, 3])
    model.fit(x_train, y_train)
    data = make_pickle(model, protocol=4)
    # sklearn models use non-standard imports but should not be OVERTLY_MALICIOUS
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity < Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"sklearn model incorrectly flagged as malicious: {result.to_string()}"
    )


# =============================================================================
# Severity Level Validation
# These tests verify specific severity levels for different patterns
# =============================================================================


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_pure_data_is_likely_safe(protocol: int) -> None:
    """Pure data (no imports) should be exactly LIKELY_SAFE."""
    data = make_pickle({"name": "test", "values": [1, 2, 3]}, protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity == Severity.LIKELY_SAFE, (
        f"Pure data should be LIKELY_SAFE, got {result.severity.name}"
    )


@pytest.mark.parametrize("protocol", HIGHER_PROTOCOLS)
def test_stdlib_with_reduce_is_at_most_suspicious(protocol: int) -> None:
    """Standard library objects using __reduce__ should be at most SUSPICIOUS.

    These objects create unused variables which is flagged by design, but
    they should never reach LIKELY_UNSAFE or above.
    """
    data = make_pickle(datetime.now(), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # datetime uses __reduce__ which creates an unused variable
    # This is correctly flagged as SUSPICIOUS but should not be higher
    assert result.severity <= Severity.SUSPICIOUS, (
        f"stdlib datetime should be at most SUSPICIOUS, got {result.severity.name}"
    )


# =============================================================================
# Known Limitations Documentation
#
# These tests document known false positives in fickling where safe stdlib
# types are flagged as malicious because they use builtins module.
# =============================================================================


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_builtins_range_is_flagged(protocol: int) -> None:
    """Document: range() is flagged because it imports from builtins.

    Protocols 0-2 use GLOBAL opcode -> LIKELY_OVERTLY_MALICIOUS.
    Protocols 3-5 use STACK_GLOBAL with safe builtins allowlist -> SUSPICIOUS.
    """
    data = make_pickle(range(10), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    if protocol <= 2:
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            f"Expected LIKELY_OVERTLY_MALICIOUS at protocol {protocol}"
        )
    else:
        assert result.severity >= Severity.SUSPICIOUS, f"Expected SUSPICIOUS at protocol {protocol}"


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_builtins_slice_is_flagged(protocol: int) -> None:
    """Document: slice() is flagged because it imports from builtins.

    Protocols 0-2 use GLOBAL opcode -> LIKELY_UNSAFE.
    Protocols 3-5 use STACK_GLOBAL with safe builtins allowlist -> SUSPICIOUS.
    """
    data = make_pickle(slice(1, 10), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    if protocol <= 2:
        assert result.severity >= Severity.LIKELY_UNSAFE, (
            f"Expected LIKELY_UNSAFE at protocol {protocol}"
        )
    else:
        assert result.severity >= Severity.SUSPICIOUS, f"Expected SUSPICIOUS at protocol {protocol}"


@pytest.mark.parametrize("protocol", [4, 5])
def test_set_at_high_protocols_is_safe(protocol: int) -> None:
    """Sets at protocols 4-5 use EMPTY_SET/ADDITEMS and are safe."""
    data = make_pickle({1, 2, 3}, protocol)
    assert_likely_safe(data)


@pytest.mark.parametrize("protocol", [4, 5])
def test_frozenset_is_likely_safe_at_high_protocols(protocol: int) -> None:
    """Document: frozenset() is LIKELY_SAFE at high protocols.

    Unlike lower protocols, protocols 4-5 serialize frozensets using the
    FROZENSET opcode, which doesn't trigger builtins import detection.
    """
    data = make_pickle(frozenset([1, 2, 3]), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # At high protocols, frozensets use special opcodes and are safe
    assert result.severity == Severity.LIKELY_SAFE, (
        f"Frozenset should be LIKELY_SAFE at protocol {protocol}, got {result.severity.name}"
    )
