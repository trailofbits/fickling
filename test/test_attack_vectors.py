"""Comprehensive attack vector tests for fickling.

These tests verify that fickling detects various malicious pickle patterns
across all pickle protocols (0-5). Each test generates malicious pickles
programmatically using __reduce__ and verifies detection.

Inspired by picklescan's malicious test samples.
"""

from __future__ import annotations

import pytest

from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled
from test._helpers import make_malicious_pickle

PROTOCOLS = [0, 1, 2, 3, 4, 5]

# Each entry: (module, func, args, test_id)
ATTACK_VECTORS = [
    pytest.param("os", "system", ("id",), id="os_system"),
    pytest.param("os", "popen", ("id",), id="os_popen"),
    pytest.param("os", "execv", ("/bin/sh", ["/bin/sh", "-c", "id"]), id="os_execv"),
    pytest.param("subprocess", "call", (["id"],), id="subprocess_call"),
    pytest.param("subprocess", "Popen", (["id"],), id="subprocess_popen"),
    pytest.param("subprocess", "run", (["id"],), id="subprocess_run"),
    pytest.param("subprocess", "check_output", (["id"],), id="subprocess_check_output"),
    pytest.param(
        "builtins",
        "eval",
        ("__import__('os').system('id')",),
        id="builtins_eval",
    ),
    pytest.param(
        "builtins",
        "exec",
        ("import os; os.system('id')",),
        id="builtins_exec",
    ),
    pytest.param(
        "builtins",
        "compile",
        ("import os; os.system('id')", "<string>", "exec"),
        id="builtins_compile",
    ),
    pytest.param("builtins", "__import__", ("os",), id="builtins_import"),
    pytest.param("builtins", "getattr", (object, "__class__"), id="builtins_getattr"),
    pytest.param(
        "socket",
        "create_connection",
        (("evil.com", 4444),),
        id="socket_create_connection",
    ),
    pytest.param("socket", "socket", (), id="socket_socket"),
    pytest.param("runpy", "run_path", ("/tmp/malicious.py",), id="runpy_run_path"),
    pytest.param("runpy", "run_module", ("os",), id="runpy_run_module"),
    pytest.param(
        "cProfile",
        "run",
        ("import os; os.system('id')",),
        id="cprofile_run",
    ),
    pytest.param("code", "InteractiveInterpreter", (), id="code_interactiveinterpreter"),
    pytest.param("importlib", "import_module", ("os",), id="importlib_import_module"),
    pytest.param("ctypes", "CDLL", ("libc.so.6",), id="ctypes_cdll"),
    pytest.param("pty", "spawn", ("/bin/sh",), id="pty_spawn"),
    pytest.param("pydoc", "locate", ("os.system",), id="pydoc_locate"),
    pytest.param(
        "multiprocessing.util",
        "spawnv_passfds",
        (b"/bin/sh", [b"/bin/sh", b"-c", b"id"], ()),
        id="multiprocessing_util_spawnv_passfds",
    ),
    pytest.param("sys", "exit", (0,), id="sys_exit"),
    pytest.param("posix", "system", ("id",), id="posix_system"),
]


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("module,func,args", ATTACK_VECTORS)
def test_attack_vector(module: str, func: str, args: tuple, protocol: int) -> None:
    """Verify fickling detects malicious module.func across all protocols."""
    data = make_malicious_pickle(module, func, args, protocol)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect {module}.{func} at protocol {protocol}"
    )


# =============================================================================
# Special cases that need non-standard pickle construction
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
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect marshal.loads at protocol {protocol}"
    )


def test_types_functiontype() -> None:
    """types.FunctionType can create executable functions.

    Uses raw opcode construction because types.FunctionType cannot be
    pickled directly using pickle.dumps with __reduce__.
    """
    import fickling.fickle as op

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
            op.EmptyTuple(),
            op.Reduce(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect types.FunctionType"
    )
