"""Archive-based attack tests for fickling.

These tests verify that fickling can detect malicious pickles embedded
in various archive formats (ZIP, TAR, etc.) that are commonly used to
distribute ML models.

Key patterns tested:
- Malicious pickle inside ZIP archives
- Malicious pickle inside TAR archives
- Nested archives with malicious content
- PyTorch-style ZIP structures with malicious pickles
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled
from test._helpers import make_benign_pickle, make_malicious_pickle

# =============================================================================
# ZIP Archive Tests
# =============================================================================


def test_malicious_pickle_in_zip() -> None:
    """Malicious pickle inside a ZIP archive should be detected."""
    malicious = make_malicious_pickle("os", "system", ("id",))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("data.pkl", malicious)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read("data.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in ZIP"
        )


def test_malicious_pickle_in_nested_zip_path() -> None:
    """Malicious pickle in nested ZIP path should be detected."""
    malicious = make_malicious_pickle("subprocess", "call", (["id"],))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Mimic PyTorch model structure
        zf.writestr("model/archive/data.pkl", malicious)
        zf.writestr("model/version", "1")

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read("model/archive/data.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in nested ZIP path"
        )


def test_zip_with_multiple_pickles_mixed() -> None:
    """ZIP with mixed benign and malicious pickles should detect malicious ones."""
    benign = make_benign_pickle([1, 2, 3])
    malicious = make_malicious_pickle("builtins", "eval", ("1+1",))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("data/safe_model.pkl", benign)
        zf.writestr("data/payload.pkl", malicious)
        zf.writestr("data/another_safe.pkl", benign)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        # Check benign pickles
        for safe_name in ["data/safe_model.pkl", "data/another_safe.pkl"]:
            pkl_data = zf.read(safe_name)
            pickled = Pickled.load(pkl_data)
            result = check_safety(pickled)
            assert result.severity == Severity.LIKELY_SAFE, (
                f"Safe pickle {safe_name} incorrectly flagged"
            )

        # Check malicious pickle
        pkl_data = zf.read("data/payload.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle among safe ones"
        )


def test_pytorch_style_zip_with_malicious_data() -> None:
    """PyTorch-style ZIP with malicious data.pkl should be detected."""
    malicious = make_malicious_pickle("socket", "socket", ())

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        # Mimic PyTorch v1.3+ format
        zf.writestr("archive/data.pkl", malicious)
        zf.writestr("archive/version", "3")
        zf.writestr("archive/data/0", b"\x00" * 100)  # Fake tensor data

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read("archive/data.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious PyTorch-style pickle"
        )


# =============================================================================
# TAR Archive Tests
# =============================================================================


def test_malicious_pickle_in_tar() -> None:
    """Malicious pickle inside a TAR archive should be detected."""
    malicious = make_malicious_pickle("os", "system", ("id",))

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        # Add malicious pickle
        pkl_io = io.BytesIO(malicious)
        info = tarfile.TarInfo(name="model.pkl")
        info.size = len(malicious)
        tf.addfile(info, pkl_io)

    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r") as tf:
        member = tf.getmember("model.pkl")
        f = tf.extractfile(member)
        assert f is not None
        pkl_data = f.read()
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in TAR"
        )


def test_malicious_pickle_in_tar_gz() -> None:
    """Malicious pickle inside a .tar.gz archive should be detected."""
    malicious = make_malicious_pickle("pty", "spawn", ("/bin/sh",))

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        pkl_io = io.BytesIO(malicious)
        info = tarfile.TarInfo(name="payload.pkl")
        info.size = len(malicious)
        tf.addfile(info, pkl_io)

    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r:gz") as tf:
        member = tf.getmember("payload.pkl")
        f = tf.extractfile(member)
        assert f is not None
        pkl_data = f.read()
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in .tar.gz"
        )


def test_legacy_pytorch_tar_with_malicious_pickle() -> None:
    """Legacy PyTorch TAR format with malicious pickle should be detected."""
    malicious = make_malicious_pickle("builtins", "exec", ("import os",))

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        # Mimic PyTorch v0.1.1 format
        pkl_io = io.BytesIO(malicious)
        info = tarfile.TarInfo(name="pickle")
        info.size = len(malicious)
        tf.addfile(info, pkl_io)

        # Add empty storages and tensors directories
        info = tarfile.TarInfo(name="storages/")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)

        info = tarfile.TarInfo(name="tensors/")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)

    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r") as tf:
        member = tf.getmember("pickle")
        f = tf.extractfile(member)
        assert f is not None
        pkl_data = f.read()
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect malicious pickle in legacy PyTorch TAR"
        )


# =============================================================================
# File-based Archive Tests
# =============================================================================


def test_zip_file_on_disk(tmp_path: Path) -> None:
    """Malicious pickle in ZIP file on disk should be detected."""
    malicious = make_malicious_pickle("os", "popen", ("id",))
    zip_path = tmp_path / "model.zip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("model.pkl", malicious)

    with zipfile.ZipFile(zip_path, "r") as zf:
        pkl_data = zf.read("model.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS


def test_tar_file_on_disk(tmp_path: Path) -> None:
    """Malicious pickle in TAR file on disk should be detected."""
    malicious = make_malicious_pickle("runpy", "run_path", ("/tmp/evil.py",))
    tar_path = tmp_path / "model.tar"

    with tarfile.open(tar_path, "w") as tf:
        pkl_io = io.BytesIO(malicious)
        info = tarfile.TarInfo(name="weights.pkl")
        info.size = len(malicious)
        tf.addfile(info, pkl_io)

    with tarfile.open(tar_path, "r") as tf:
        member = tf.getmember("weights.pkl")
        f_extracted = tf.extractfile(member)
        assert f_extracted is not None
        pkl_data = f_extracted.read()
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS


# =============================================================================
# Edge Cases
# =============================================================================


def test_zip_with_non_pickle_binary() -> None:
    """ZIP with non-pickle binary data should not be confused for pickle."""
    # Create some random binary data that's not a pickle
    random_data = b"\x00\x01\x02\x03\xff\xfe\xfd" * 100

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("model.bin", random_data)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        bin_data = zf.read("model.bin")
        with pytest.raises(ValueError):
            Pickled.load(bin_data)


def test_deeply_nested_malicious_pickle() -> None:
    """Deeply nested malicious pickle should still be detected."""
    malicious = make_malicious_pickle("ctypes", "CDLL", ("libc.so.6",))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("level1/level2/level3/level4/deep_model.pkl", malicious)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read("level1/level2/level3/level4/deep_model.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            "Failed to detect deeply nested malicious pickle"
        )


# =============================================================================
# Protocol Version Tests in Archives
# =============================================================================


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_all_protocols_in_zip(protocol: int) -> None:
    """All pickle protocols should be detected in ZIP archives."""
    malicious = make_malicious_pickle("os", "system", ("id",), protocol=protocol)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(f"model_proto{protocol}.pkl", malicious)

    buffer.seek(0)
    with zipfile.ZipFile(buffer, "r") as zf:
        pkl_data = zf.read(f"model_proto{protocol}.pkl")
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            f"Failed to detect malicious pickle at protocol {protocol} in ZIP"
        )


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_all_protocols_in_tar(protocol: int) -> None:
    """All pickle protocols should be detected in TAR archives."""
    malicious = make_malicious_pickle("os", "system", ("id",), protocol=protocol)

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        pkl_io = io.BytesIO(malicious)
        info = tarfile.TarInfo(name=f"model_proto{protocol}.pkl")
        info.size = len(malicious)
        tf.addfile(info, pkl_io)

    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r") as tf:
        member = tf.getmember(f"model_proto{protocol}.pkl")
        f = tf.extractfile(member)
        assert f is not None
        pkl_data = f.read()
        pickled = Pickled.load(pkl_data)
        result = check_safety(pickled)
        assert result.severity >= Severity.LIKELY_OVERTLY_MALICIOUS, (
            f"Failed to detect malicious pickle at protocol {protocol} in TAR"
        )
