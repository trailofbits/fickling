import os
import pickle
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from fickling.cli import main
from fickling.constants import EXIT_CLEAN, EXIT_ERROR, EXIT_UNSAFE


class Payload:
    """Malicious payload for testing (executes os.system on unpickle)."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


def _write_pickle(path: Path, obj) -> None:
    with open(path, "wb") as f:
        pickle.dump(obj, f)


def _run(*argv) -> int:
    """Invoke the CLI and swallow stdout to keep test output clean."""
    with redirect_stdout(StringIO()):
        return main(["fickling", *argv])


class TestRecursiveDirectoryScan(unittest.TestCase):
    def test_directory_with_unsafe_file_returns_exit_unsafe(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "safe.pkl", [1, 2, 3])
            _write_pickle(root / "evil.pkl", Payload())
            self.assertEqual(_run(str(root)), EXIT_UNSAFE)

    def test_all_safe_directory_returns_exit_clean(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "a.pkl", [1, 2, 3])
            _write_pickle(root / "b.pickle", {"k": "v"})
            _write_pickle(root / "c.bin", 42)
            self.assertEqual(_run(str(root)), EXIT_CLEAN)

    def test_directory_without_pickle_files_returns_exit_clean(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "README.md").write_text("not a pickle")
            (root / "config.json").write_text("{}")
            self.assertEqual(_run(str(root)), EXIT_CLEAN)

    def test_nonrecursive_does_not_descend_into_subdirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "safe.pkl", [1, 2, 3])
            nested = root / "nested"
            nested.mkdir()
            _write_pickle(nested / "evil.pkl", Payload())
            # Default (non-recursive) must ignore the nested unsafe file.
            self.assertEqual(_run(str(root)), EXIT_CLEAN)

    def test_recursive_descends_into_subdirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "safe.pkl", [1, 2, 3])
            nested = root / "nested" / "deeper"
            nested.mkdir(parents=True)
            _write_pickle(nested / "evil.pkl", Payload())
            self.assertEqual(_run(str(root), "--recursive"), EXIT_UNSAFE)

    def test_recursive_short_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            nested = root / "sub"
            nested.mkdir()
            _write_pickle(nested / "evil.pkl", Payload())
            self.assertEqual(_run(str(root), "-R"), EXIT_UNSAFE)

    def test_nonexistent_target_returns_exit_error(self):
        # A directory/glob scan of a path that resolves to nothing reports
        # EXIT_ERROR rather than a misleading "clean" result.
        self.assertEqual(_run("/nonexistent/directory/xyz", "--recursive"), EXIT_ERROR)


class TestGlobScan(unittest.TestCase):
    def test_glob_matches_unsafe_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "safe.pkl", [1, 2, 3])
            _write_pickle(root / "evil.pkl", Payload())
            self.assertEqual(_run(str(root / "*.pkl")), EXIT_UNSAFE)

    def test_glob_only_safe_matches(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "a.pkl", [1, 2, 3])
            _write_pickle(root / "evil.bin", Payload())
            # Glob restricted to *.pkl must not pick up the unsafe .bin file.
            self.assertEqual(_run(str(root / "*.pkl")), EXIT_CLEAN)

    def test_glob_no_matches_returns_exit_error(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertEqual(_run(str(root / "*.pkl")), EXIT_ERROR)

    def test_recursive_glob(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            nested = root / "a" / "b"
            nested.mkdir(parents=True)
            _write_pickle(nested / "evil.pkl", Payload())
            pattern = str(root / "**" / "*.pkl")
            self.assertEqual(_run(pattern, "--recursive"), EXIT_UNSAFE)


class TestZipMemberScan(unittest.TestCase):
    def test_pt_archive_with_unsafe_member(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "model.pt"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("data.pkl", pickle.dumps(Payload()))
            self.assertEqual(_run(str(root)), EXIT_UNSAFE)

    def test_pth_archive_all_safe(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "model.pth"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("weights.pkl", pickle.dumps([1, 2, 3]))
            self.assertEqual(_run(str(root)), EXIT_CLEAN)


class TestSingleFileUnaffected(unittest.TestCase):
    def test_recursive_flag_on_single_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(Payload(), f)
            path = f.name
        try:
            self.assertEqual(_run(path, "--recursive"), EXIT_UNSAFE)
        finally:
            Path(path).unlink()

    def test_print_results_emits_summary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_pickle(root / "evil.pkl", Payload())
            buf = StringIO()
            with redirect_stdout(buf):
                code = main(["fickling", str(root), "--print-results"])
            self.assertEqual(code, EXIT_UNSAFE)
            self.assertIn("Potentially unsafe content detected", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
