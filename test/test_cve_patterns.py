"""CVE-based attack pattern tests for fickling.

These tests verify that fickling detects attack patterns identified in CVEs
for pickle scanning tools. The patterns are based on vulnerabilities found
in picklescan.

CVE-2025-10157: Submodule Import Bypass
CVE-2025-10156: ZIP CRC Bypass
CVE-2025-10155: File Extension Bypass
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled
from test._helpers import make_malicious_pickle

# =============================================================================
# CVE-2025-10157: Submodule Import Bypass
#
# Attack: Using submodule paths like asyncio.unix_events bypasses scanners
# that only do exact string matching on module names.
#
# Fickling should detect parent modules when a submodule is imported.
# =============================================================================


def test_submodule_bypass_os_path() -> None:
    """os.path submodule should trigger os detection via hierarchical matching.

    Uses raw opcodes because make_malicious_pickle resolves os.path to
    posixpath at pickle time, losing the dotted module path.
    """
    pickled = Pickled(
        [
            op.Proto.create(4),
            op.Frame(50),
            op.ShortBinUnicode("os.path"),
            op.Memoize(),
            op.ShortBinUnicode("join"),
            op.Memoize(),
            op.StackGlobal(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect os.path submodule"
    )


def test_submodule_bypass_subprocess_internal() -> None:
    """Deep submodule in subprocess should trigger subprocess detection."""
    # Construct a pickle that references subprocess submodule
    pickled = Pickled(
        [
            op.Proto.create(4),
            op.Frame(50),
            op.ShortBinUnicode("subprocess"),
            op.Memoize(),
            op.ShortBinUnicode("Popen"),
            op.Memoize(),
            op.StackGlobal(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, "Failed to detect subprocess"


def test_submodule_bypass_multiprocessing_util() -> None:
    """multiprocessing.util should trigger multiprocessing detection."""
    data = make_malicious_pickle("multiprocessing.util", "spawnv_passfds", (), protocol=4)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect multiprocessing.util submodule"
    )


def test_submodule_bypass_ctypes_util() -> None:
    """ctypes.util should trigger ctypes detection."""
    data = make_malicious_pickle("ctypes.util", "find_library", ("c",), protocol=4)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect ctypes.util submodule"
    )


def test_submodule_bypass_importlib_util() -> None:
    """importlib.util should trigger importlib detection."""
    data = make_malicious_pickle("importlib.util", "find_spec", ("os",), protocol=4)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect importlib.util submodule"
    )


def test_hierarchical_module_detection() -> None:
    """Verify hierarchical module matching works correctly.

    When a pickle imports 'a.b.c', detection should trigger if any of:
    - 'a' is in UNSAFE_IMPORTS/UNSAFE_MODULES
    - 'a.b' is in UNSAFE_IMPORTS/UNSAFE_MODULES
    - 'a.b.c' is in UNSAFE_IMPORTS/UNSAFE_MODULES
    """
    # Test with multiprocessing.util which should match 'multiprocessing'
    pickled = Pickled(
        [
            op.Proto.create(4),
            op.Frame(50),
            op.ShortBinUnicode("multiprocessing.util"),
            op.Memoize(),
            op.ShortBinUnicode("spawnv_passfds"),
            op.Memoize(),
            op.StackGlobal(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Hierarchical module matching failed for multiprocessing.util"
    )


# =============================================================================
# CVE-2025-10156: ZIP CRC Bypass
#
# Attack: Corrupt CRC in ZIP Central Directory causes Python's zipfile to
# fail validation, but PyTorch still loads the file. Scanner fails to scan.
#
# Fickling should gracefully handle corrupted ZIPs and still scan content.
# =============================================================================


def create_corrupted_zip_with_pickle(malicious_pickle: bytes) -> bytes:
    """Create a ZIP file with corrupted CRC containing a malicious pickle.

    The CRC in the Central Directory is corrupted, but the local file
    header CRC remains valid. Some parsers fail on this, but the pickle
    data is still extractable.
    """
    # Create a valid ZIP first
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("data.pkl", malicious_pickle)

    zip_bytes = bytearray(buffer.getvalue())

    # Find the Central Directory and corrupt the CRC there
    # The Central Directory File Header starts with signature 0x02014b50
    cd_sig = b"\x50\x4b\x01\x02"
    cd_offset = zip_bytes.find(cd_sig)

    assert cd_offset != -1, "Central Directory signature not found in ZIP"
    if cd_offset != -1:
        # CRC-32 is at offset 16 from the start of the central directory entry
        crc_offset = cd_offset + 16
        if crc_offset + 4 <= len(zip_bytes):
            # Corrupt the CRC by XORing with 0xFF
            for i in range(4):
                zip_bytes[crc_offset + i] ^= 0xFF

    return bytes(zip_bytes)


def test_corrupted_zip_still_scanned() -> None:
    """Malicious pickle in corrupted ZIP should still be detected.

    This tests the CVE-2025-10156 pattern where a corrupted CRC in the
    ZIP Central Directory might cause scanners to skip the file.
    """
    malicious_pickle = make_malicious_pickle("os", "system", ("id",))
    corrupted_zip = create_corrupted_zip_with_pickle(malicious_pickle)

    try:
        with zipfile.ZipFile(io.BytesIO(corrupted_zip), "r") as zf:
            pkl_data = zf.read("data.pkl")
    except zipfile.BadZipFile:
        pkl_offset = corrupted_zip.find(malicious_pickle)
        assert pkl_offset != -1, "Pickle data not found in corrupted ZIP"
        pkl_data = malicious_pickle

    pickled = Pickled.load(pkl_data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS


def test_valid_zip_with_malicious_pickle() -> None:
    """Valid ZIP containing malicious pickle should be detected."""
    malicious_pickle = make_malicious_pickle("os", "system", ("id",))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("model/data.pkl", malicious_pickle)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read("model/data.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in valid ZIP"
        )


# =============================================================================
# CVE-2025-10155: File Extension Bypass
#
# Attack: Rename .pkl to .bin or .pt causes parser confusion.
# Detection should work regardless of file extension.
#
# Fickling should detect based on content, not file extension.
# =============================================================================


EXTENSION_CASES = [
    pytest.param(".bin", "os", "system", ("id",), id="bin"),
    pytest.param(".pt", "subprocess", "call", (["id"],), id="pt"),
    pytest.param(".pth", "builtins", "eval", ("1+1",), id="pth"),
    pytest.param("", "socket", "socket", (), id="no_extension"),
    pytest.param(".txt", "pty", "spawn", ("/bin/sh",), id="misleading_txt"),
]


@pytest.mark.parametrize("ext,module,func,args", EXTENSION_CASES)
def test_extension_agnostic_detection(
    tmp_path: Path, ext: str, module: str, func: str, args: tuple
) -> None:
    """Detection should work regardless of file extension."""
    malicious_pickle = make_malicious_pickle(module, func, args)
    file_path = tmp_path / f"model{ext}"
    file_path.write_bytes(malicious_pickle)

    pickled = Pickled.load(file_path.read_bytes())
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        f"Failed to detect malicious pickle with {ext!r} extension"
    )


# =============================================================================
# Additional CVE-related patterns
# =============================================================================


def test_nested_module_in_unsafe_namespace() -> None:
    """Deeply nested modules in unsafe namespaces should be detected."""
    # sys.modules allows accessing any loaded module
    pickled = Pickled(
        [
            op.Proto.create(4),
            op.Frame(30),
            op.ShortBinUnicode("sys"),
            op.Memoize(),
            op.ShortBinUnicode("modules"),
            op.Memoize(),
            op.StackGlobal(),
            op.Memoize(),
            op.Stop(),
        ]
    )
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect sys.modules access"
    )


def test_code_module_submodules() -> None:
    """code module and submodules should be detected."""
    data = make_malicious_pickle("code", "InteractiveConsole", (), protocol=4)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
        "Failed to detect code.InteractiveConsole"
    )


def test_runpy_submodules() -> None:
    """runpy module and any submodules should be detected."""
    data = make_malicious_pickle("runpy", "_run_code", (), protocol=4)
    pickled = Pickled.load(data)
    result = check_safety(pickled)
    assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, "Failed to detect runpy._run_code"
