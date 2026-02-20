import os
import pickle
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fickling.analysis import Severity
from fickling.fickle import PickleDecodeError
from fickling.loader import RelaxedZipFile, ScanResult, scan_archive, scan_file


class Payload:
    """Malicious payload for testing."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


def _create_zip_with_pickle(zip_path, member_name, data):
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(member_name, data)


class TestScanFile(unittest.TestCase):
    def test_detects_malicious_payload(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(Payload(), f)
            path = f.name
        try:
            result = scan_file(path)
            self.assertFalse(result.is_safe)
            self.assertGreater(result.severity, Severity.LIKELY_SAFE)
            self.assertGreater(len(result.results), 0)
            self.assertEqual(result.filepath, path)
        finally:
            Path(path).unlink()

    def test_safe_data(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump([1, 2, 3], f)
            path = f.name
        try:
            result = scan_file(path)
            self.assertTrue(result.is_safe)
            self.assertEqual(result.severity, Severity.LIKELY_SAFE)
            self.assertEqual(result.errors, [])
        finally:
            Path(path).unlink()

    def test_graceful_corrupted(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"\x00\x01\x02\x03corrupt")
            path = f.name
        try:
            result = scan_file(path, graceful=True)
            self.assertIsInstance(result, ScanResult)
            self.assertFalse(bool(result))
            self.assertGreater(len(result.errors), 0)
        finally:
            Path(path).unlink()

    def test_non_graceful_corrupted_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"\x00\x01\x02\x03corrupt")
            path = f.name
        try:
            with self.assertRaises(PickleDecodeError):
                scan_file(path, graceful=False)
        finally:
            Path(path).unlink()

    def test_nonexistent_graceful(self):
        result = scan_file("/nonexistent/path.pkl", graceful=True)
        self.assertIsInstance(result, ScanResult)
        self.assertFalse(bool(result))
        self.assertGreater(len(result.errors), 0)
        self.assertEqual(result.severity, Severity.SUSPICIOUS)

    def test_nonexistent_non_graceful_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_file("/nonexistent/path.pkl", graceful=False)

    def test_graceful_analysis_error_escalates_to_likely_unsafe(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump([1, 2, 3], f)
            path = f.name
        try:
            with patch(
                "fickling.loader.check_safety",
                side_effect=RuntimeError("analysis bug"),
            ):
                result = scan_file(path, graceful=True)
            self.assertGreaterEqual(result.severity, Severity.LIKELY_UNSAFE)
            self.assertFalse(bool(result))
            self.assertTrue(any("Analysis error" in e for e in result.errors))
        finally:
            Path(path).unlink()


class TestScanArchive(unittest.TestCase):
    def test_detects_malicious_pkl(self):
        malicious_data = pickle.dumps(Payload())
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            _create_zip_with_pickle(zip_path, "model.pkl", malicious_data)
            results = scan_archive(zip_path)
            self.assertIn("model.pkl", results)
            self.assertFalse(results["model.pkl"].is_safe)
        finally:
            Path(zip_path).unlink()

    def test_skips_non_pickle_extensions(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("readme.txt", b"hello")
                zf.writestr("model.pkl", pickle.dumps([1, 2, 3]))
            results = scan_archive(zip_path)
            self.assertNotIn("readme.txt", results)
            self.assertIn("model.pkl", results)
        finally:
            Path(zip_path).unlink()

    def test_scans_all_pickle_extensions(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            safe_data = pickle.dumps(42)
            with zipfile.ZipFile(zip_path, "w") as zf:
                for ext in ("pkl", "pickle", "bin", "pt", "pth"):
                    zf.writestr(f"model.{ext}", safe_data)
            results = scan_archive(zip_path)
            self.assertEqual(len(results), 5)
        finally:
            Path(zip_path).unlink()

    def test_bad_zip_graceful(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"not a zip file at all")
            bad_path = f.name
        try:
            results = scan_archive(bad_path, graceful=True)
            self.assertIn("<archive>", results)
            self.assertGreater(len(results["<archive>"].errors), 0)
        finally:
            Path(bad_path).unlink()

    def test_bad_zip_non_graceful_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"not a zip file at all")
            bad_path = f.name
        try:
            with self.assertRaises(zipfile.BadZipFile):
                scan_archive(bad_path, graceful=False)
        finally:
            Path(bad_path).unlink()

    def test_nonexistent_graceful(self):
        results = scan_archive("/nonexistent/archive.zip", graceful=True)
        self.assertIn("<archive>", results)
        self.assertGreater(len(results["<archive>"].errors), 0)

    def test_nonexistent_non_graceful_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_archive("/nonexistent/archive.zip", graceful=False)

    def test_graceful_mixed_good_and_bad_members(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("good.pkl", pickle.dumps([1, 2, 3]))
                zf.writestr("bad.pkl", b"\x00\x01corrupt_pickle")
            results = scan_archive(zip_path, graceful=True)
            self.assertIn("good.pkl", results)
            self.assertIn("bad.pkl", results)
            self.assertTrue(results["good.pkl"].is_safe)
            self.assertGreater(len(results["bad.pkl"].errors), 0)
        finally:
            Path(zip_path).unlink()


class TestScanResult(unittest.TestCase):
    def test_bool_contract(self):
        safe = ScanResult(
            filepath="a.pkl",
            severity=Severity.LIKELY_SAFE,
            results=[],
            errors=[],
        )
        self.assertTrue(bool(safe))

        unsafe = ScanResult(
            filepath="b.pkl",
            severity=Severity.LIKELY_UNSAFE,
            results=[],
            errors=[],
        )
        self.assertFalse(bool(unsafe))

        with_errors = ScanResult(
            filepath="c.pkl",
            severity=Severity.LIKELY_SAFE,
            results=[],
            errors=["some error"],
        )
        self.assertFalse(bool(with_errors))

    def test_is_safe_boundary_at_possibly_unsafe(self):
        result = ScanResult(
            filepath="x.pkl",
            severity=Severity.POSSIBLY_UNSAFE,
            results=[],
            errors=[],
        )
        self.assertFalse(result.is_safe)

    def test_repr(self):
        sr = ScanResult(
            filepath="test.pkl",
            severity=Severity.SUSPICIOUS,
            results=[],
            errors=["err"],
        )
        r = repr(sr)
        self.assertIn("test.pkl", r)
        self.assertIn("SUSPICIOUS", r)
        self.assertIn("results=0", r)
        self.assertIn("errors=1", r)


class TestRelaxedZipFile(unittest.TestCase):
    def test_reads_valid_files(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("data.pkl", pickle.dumps({"key": "value"}))
            with RelaxedZipFile(zip_path, "r") as rzf:
                data = rzf.read("data.pkl")
                self.assertIsNotNone(data)
                obj = pickle.loads(data)
                self.assertEqual(obj, {"key": "value"})
        finally:
            Path(zip_path).unlink()

    def test_reads_file_with_bad_crc(self):
        content = b"test pickle data"
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            zip_path = f.name
        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("data.pkl", content)

            # Corrupt the CRC-32 in the central directory entry
            # (offset 16 from PK\x01\x02 signature)
            raw = bytearray(Path(zip_path).read_bytes())
            cd_sig = b"PK\x01\x02"
            cd_idx = raw.find(cd_sig)
            crc_offset = cd_idx + 16
            raw[crc_offset : crc_offset + 4] = struct.pack("<I", 0xDEADBEEF)
            Path(zip_path).write_bytes(raw)

            # Standard ZipFile should raise on read
            with zipfile.ZipFile(zip_path, "r") as zf:
                with self.assertRaises(zipfile.BadZipFile):
                    zf.read("data.pkl")

            # RelaxedZipFile should succeed
            with RelaxedZipFile(zip_path, "r") as rzf:
                data = rzf.read("data.pkl")
                self.assertEqual(data, content)
        finally:
            Path(zip_path).unlink()
