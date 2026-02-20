"""Tests for the fickling CLI."""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from pickle import dumps
from unittest import TestCase

import pytest

from fickling.cli import _get_first_positional, main
from fickling.constants import EXIT_CLEAN, EXIT_ERROR, EXIT_UNSAFE


class TestCLIBackwardCompatibility(TestCase):
    """Test that existing CLI behavior is preserved."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_version_flag(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "--version"])
        self.assertEqual(result, EXIT_CLEAN)
        # isatty() is False for StringIO, so output is just the version number
        output = stdout.getvalue().strip()
        self.assertTrue(output)
        self.assertRegex(output, r"^\d+\.\d+\.\d+")

    def test_version_flag_short(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "-v"])
        self.assertEqual(result, EXIT_CLEAN)
        output = stdout.getvalue().strip()
        self.assertTrue(output)

    def test_decompile_pickle(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)
        output = stdout.getvalue()
        self.assertIn("result", output)
        self.assertIn("test", output)

    def test_check_safety_legacy_flag(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "--check-safety", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)

    def test_check_safety_legacy_stdin(self):
        """Legacy --check-safety supports stdin via default '-' file arg."""
        # Verify the parser accepts --check-safety without a file argument
        # (file defaults to "-" for stdin)
        from fickling.cli import _create_legacy_parser

        parser = _create_legacy_parser()
        args = parser.parse_args(["--check-safety"])
        self.assertTrue(args.check_safety)
        self.assertEqual(args.file, "-")

    def test_legacy_mutually_exclusive_flags(self):
        """--inject, --check-safety, --create are mutually exclusive."""
        with self.assertRaises(SystemExit):
            main(
                [
                    "fickling",
                    "--check-safety",
                    "--inject",
                    "code",
                    str(self.pickle_file),
                ]
            )

    def test_help_flag(self):
        with self.assertRaises(SystemExit) as cm:
            main(["fickling", "--help"])
        self.assertEqual(cm.exception.code, 0)


class TestGetFirstPositional(TestCase):
    """Test the _get_first_positional routing function."""

    def test_simple_command(self):
        self.assertEqual(
            _get_first_positional(["fickling", "check", "file.pkl"]),
            "check",
        )

    def test_flag_value_not_misrouted(self):
        """Flag values matching command names must not be treated as commands."""
        self.assertEqual(
            _get_first_positional(["fickling", "--inject", "check", "file.pkl"]),
            "file.pkl",
        )

    def test_short_flag_value_not_misrouted(self):
        self.assertEqual(
            _get_first_positional(["fickling", "-i", "check", "file.pkl"]),
            "file.pkl",
        )

    def test_no_positional(self):
        self.assertIsNone(
            _get_first_positional(["fickling", "--version"]),
        )

    def test_file_path_as_first_positional(self):
        self.assertEqual(
            _get_first_positional(["fickling", "file.pkl"]),
            "file.pkl",
        )

    def test_create_flag_value_skipped(self):
        self.assertEqual(
            _get_first_positional(["fickling", "--create", "expr", "out.pkl"]),
            "out.pkl",
        )


class TestCheckCommand(TestCase):
    """Test the 'fickling check' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_check_pickle(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)
        output = stdout.getvalue()
        self.assertIn("Detected format", output)
        self.assertIn("pickle", output)
        self.assertIn("No unsafe operations detected", output)

    def test_check_json_output(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", "--json", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["format"], "pickle")
        self.assertTrue(data["safe"])
        self.assertIn("severity", data)
        self.assertIn("results", data)

    def test_check_file_not_found(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "check", "/nonexistent/file.pkl"])
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("file not found", stderr.getvalue())

    def test_check_print_results(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", "--print-results", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)


class TestCheckCommandPyTorch(TestCase):
    """Test 'fickling check' on PyTorch models (requires torch)."""

    @classmethod
    def setUpClass(cls):
        pytest.importorskip("torch")
        pytest.importorskip("torchvision")

    def setUp(self):
        import torch
        import torchvision.models as models

        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_check_pytorch_model(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", str(self.model_file)])
        self.assertIn(result, [EXIT_CLEAN, EXIT_UNSAFE])
        output = stdout.getvalue()
        self.assertIn("Detected format", output)
        self.assertIn("PyTorch", output)


class TestInjectCommand(TestCase):
    """Test the 'fickling inject' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_inject_pickle(self):
        output_file = self.tmppath / "injected.pkl"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(
                [
                    "fickling",
                    "inject",
                    str(self.pickle_file),
                    "-c",
                    "print('test')",
                    "-o",
                    str(output_file),
                ]
            )
        self.assertEqual(result, EXIT_CLEAN)
        self.assertTrue(output_file.exists())
        self.assertGreater(output_file.stat().st_size, 0)

    def test_inject_missing_output(self):
        with self.assertRaises(SystemExit):
            main(["fickling", "inject", str(self.pickle_file), "-c", "code"])

    def test_inject_missing_code(self):
        with self.assertRaises(SystemExit):
            main(["fickling", "inject", str(self.pickle_file), "-o", "out.pkl"])

    def test_inject_file_not_found(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(
                [
                    "fickling",
                    "inject",
                    "/nonexistent/file.pkl",
                    "-c",
                    "code",
                    "-o",
                    "out.pkl",
                ]
            )
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("file not found", stderr.getvalue())

    def test_inject_output_exists_no_overwrite(self):
        output_file = self.tmppath / "existing.pkl"
        output_file.write_bytes(b"existing")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(
                [
                    "fickling",
                    "inject",
                    str(self.pickle_file),
                    "-c",
                    "print('test')",
                    "-o",
                    str(output_file),
                ]
            )
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("already exists", stderr.getvalue())


class TestInjectCommandPyTorch(TestCase):
    """Test 'fickling inject' on PyTorch models (requires torch)."""

    @classmethod
    def setUpClass(cls):
        pytest.importorskip("torch")
        pytest.importorskip("torchvision")

    def setUp(self):
        import torch
        import torchvision.models as models

        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_inject_pytorch_model(self):
        output_file = self.tmppath / "injected.pth"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(
                [
                    "fickling",
                    "inject",
                    str(self.model_file),
                    "-c",
                    "print('test')",
                    "-o",
                    str(output_file),
                ]
            )
        self.assertEqual(result, EXIT_CLEAN)
        self.assertTrue(output_file.exists())

    def test_inject_pytorch_combination_method(self):
        output_file = self.tmppath / "injected_combo.pth"
        result = main(
            [
                "fickling",
                "inject",
                str(self.model_file),
                "-c",
                "print('test')",
                "-o",
                str(output_file),
                "--method",
                "combination",
            ]
        )
        self.assertEqual(result, EXIT_CLEAN)
        self.assertTrue(output_file.exists())


class TestInfoCommand(TestCase):
    """Test 'fickling info' on plain pickle (no torch required)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_info_pickle(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", str(self.pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)
        output = stdout.getvalue()
        self.assertIn("Format:", output)

    def test_info_file_not_found(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "info", "/nonexistent/file.pth"])
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("file not found", stderr.getvalue())


class TestInfoCommandPyTorch(TestCase):
    """Test 'fickling info' on PyTorch models (requires torch)."""

    @classmethod
    def setUpClass(cls):
        pytest.importorskip("torch")
        pytest.importorskip("torchvision")

    def setUp(self):
        import torch
        import torchvision.models as models

        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_info_pytorch_model(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", str(self.model_file)])
        self.assertEqual(result, EXIT_CLEAN)
        output = stdout.getvalue()
        self.assertIn("Format:", output)
        self.assertIn("PyTorch", output)

    def test_info_json_output(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", "--json", str(self.model_file)])
        self.assertEqual(result, EXIT_CLEAN)
        data = json.loads(stdout.getvalue())
        self.assertIn("formats", data)
        self.assertIn("primary_format", data)
        self.assertIn("properties", data)


class TestCreatePolyglotCommand(TestCase):
    """Test the 'fickling create-polyglot' command (requires torch)."""

    @classmethod
    def setUpClass(cls):
        pytest.importorskip("torch")
        pytest.importorskip("torchvision")

    def setUp(self):
        import torch
        import torchvision.models as models

        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_create_polyglot_file_not_found(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(
                [
                    "fickling",
                    "create-polyglot",
                    "/nonexistent/file1.pth",
                    str(self.model_file),
                ]
            )
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("file not found", stderr.getvalue())


class TestAutoLoad(TestCase):
    """Test the auto_load() format detection function."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_auto_load_pickle(self):
        from fickling.loader import auto_load

        pickle_file = self.tmppath / "test.pkl"
        with open(pickle_file, "wb") as f:
            f.write(dumps({"key": "value"}))

        format_name, stacked = auto_load(pickle_file)
        self.assertEqual(format_name, "pickle")
        self.assertGreater(len(stacked), 0)

    def test_auto_load_file_not_found(self):
        from fickling.loader import auto_load

        with self.assertRaises(FileNotFoundError):
            auto_load(Path("/nonexistent/file.pkl"))

    def test_auto_load_invalid_file(self):
        from fickling.loader import auto_load

        bad_file = self.tmppath / "bad.pkl"
        bad_file.write_bytes(b"not a pickle at all")
        with self.assertRaises(ValueError):
            auto_load(bad_file)

    def test_auto_load_string_path(self):
        from fickling.loader import auto_load

        pickle_file = self.tmppath / "test.pkl"
        with open(pickle_file, "wb") as f:
            f.write(dumps([1, 2, 3]))

        format_name, stacked = auto_load(str(pickle_file))
        self.assertEqual(format_name, "pickle")


class TestCLIExitCodes(TestCase):
    """Test that exit codes follow ClamAV convention."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_safe_pickle_returns_exit_clean(self):
        pickle_file = self.tmppath / "safe.pkl"
        with open(pickle_file, "wb") as f:
            f.write(dumps({"safe": True}))

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", str(pickle_file)])
        self.assertEqual(result, EXIT_CLEAN)

    def test_file_not_found_returns_exit_error(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "check", "/nonexistent/file.pkl"])
        self.assertEqual(result, EXIT_ERROR)

    def test_version_returns_exit_clean(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "--version"])
        self.assertEqual(result, EXIT_CLEAN)


class TestCLIErrorHandling(TestCase):
    """Test CLI error handling."""

    def test_nonexistent_pickle_file(self):
        with self.assertRaises(FileNotFoundError):
            main(["fickling", "/nonexistent/file.pkl"])
