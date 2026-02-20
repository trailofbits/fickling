import os
import pickle
import tempfile
import unittest
import zipfile
from pathlib import Path

from fickling.analysis import Severity
from fickling.fickle import PickleDecodeError
from fickling.loader import ScanResult, scan_archive, scan_file
from fickling.polyglot import RelaxedZipFile


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
            with self.assertRaises((PickleDecodeError, ValueError)):
                scan_file(path, graceful=False)
        finally:
            Path(path).unlink()

    def test_nonexistent_graceful(self):
        result = scan_file("/nonexistent/path.pkl", graceful=True)
        self.assertIsInstance(result, ScanResult)
        self.assertFalse(bool(result))
        self.assertGreater(len(result.errors), 0)

    def test_nonexistent_non_graceful_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_file("/nonexistent/path.pkl", graceful=False)


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
