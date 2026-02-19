"""Tests for the fickling CLI."""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from pickle import dumps
from unittest import TestCase

import torch
import torchvision.models as models

from fickling.cli import main


class TestCLIBackwardCompatibility(TestCase):
    """Test that existing CLI behavior is preserved."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a simple pickle file
        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_version_flag(self):
        """Test --version flag."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "--version"])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should contain version number
        self.assertTrue(output.strip())

    def test_decompile_pickle(self):
        """Test basic pickle decompilation."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", str(self.pickle_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should contain decompiled code
        self.assertIn("result", output)

    def test_check_safety_legacy_flag(self):
        """Test --check-safety on a safe pickle file (legacy syntax)."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "--check-safety", str(self.pickle_file)])
        self.assertEqual(result, 0)

    def test_help_flag(self):
        """Test --help flag."""
        with self.assertRaises(SystemExit) as cm:
            main(["fickling", "--help"])
        self.assertEqual(cm.exception.code, 0)


class TestCheckCommand(TestCase):
    """Test the 'fickling check' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a simple pickle file
        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_check_pickle(self):
        """Test 'fickling check' on a pickle file."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", str(self.pickle_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Detected format", output)
        self.assertIn("pickle", output)

    def test_check_pytorch_model(self):
        """Test 'fickling check' on a PyTorch model (auto-detection)."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", str(self.model_file)])
        # Result can be 0 (safe) or 1 (potentially unsafe) - just verify it runs
        self.assertIn(result, [0, 1])
        output = stdout.getvalue()
        self.assertIn("Detected format", output)
        self.assertIn("PyTorch", output)

    def test_check_json_output(self):
        """Test 'fickling check --json'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "check", "--json", str(self.pickle_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should be valid JSON
        data = json.loads(output)
        self.assertIn("format", data)
        self.assertIn("safe", data)
        self.assertIn("severity", data)

    def test_check_file_not_found(self):
        """Test 'fickling check' with non-existent file."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "check", "/nonexistent/file.pkl"])
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestInjectCommand(TestCase):
    """Test the 'fickling inject' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a simple pickle file
        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_inject_pickle(self):
        """Test 'fickling inject' on a pickle file."""
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
        self.assertEqual(result, 0)
        self.assertTrue(output_file.exists())

    def test_inject_pytorch_model(self):
        """Test 'fickling inject' on a PyTorch model."""
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
        self.assertEqual(result, 0)
        self.assertTrue(output_file.exists())

    def test_inject_pytorch_combination_method(self):
        """Test 'fickling inject --method combination' on a PyTorch model."""
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
        self.assertEqual(result, 0)
        self.assertTrue(output_file.exists())

    def test_inject_missing_output(self):
        """Test inject without required --output flag."""
        with self.assertRaises(SystemExit):
            main(["fickling", "inject", str(self.pickle_file), "-c", "code"])

    def test_inject_missing_code(self):
        """Test inject without required --code flag."""
        with self.assertRaises(SystemExit):
            main(["fickling", "inject", str(self.pickle_file), "-o", "out.pkl"])

    def test_inject_file_not_found(self):
        """Test inject with non-existent file."""
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
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestInfoCommand(TestCase):
    """Test the 'fickling info' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a simple pickle file
        self.pickle_file = self.tmppath / "test.pkl"
        with open(self.pickle_file, "wb") as f:
            f.write(dumps({"test": "data"}))

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_info_pickle(self):
        """Test 'fickling info' on a pickle file."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", str(self.pickle_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Format:", output)

    def test_info_pytorch_model(self):
        """Test 'fickling info' on a PyTorch model."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Format:", output)
        self.assertIn("PyTorch", output)

    def test_info_json_output(self):
        """Test 'fickling info --json'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "info", "--json", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should be valid JSON
        data = json.loads(output)
        self.assertIn("formats", data)
        self.assertIn("primary_format", data)
        self.assertIn("properties", data)

    def test_info_file_not_found(self):
        """Test info with non-existent file."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "info", "/nonexistent/file.pth"])
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestCreatePolyglotCommand(TestCase):
    """Test the 'fickling create-polyglot' command."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_create_polyglot_file_not_found(self):
        """Test create-polyglot with non-existent file."""
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
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestCLIErrorHandling(TestCase):
    """Test CLI error handling."""

    def test_nonexistent_pickle_file(self):
        """Test decompiling non-existent file raises FileNotFoundError."""
        # The original CLI raises FileNotFoundError for non-existent files
        with self.assertRaises(FileNotFoundError):
            main(["fickling", "/nonexistent/file.pkl"])
