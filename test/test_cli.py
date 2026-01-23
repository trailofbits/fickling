"""Tests for the fickling CLI."""

from __future__ import annotations

import io
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

    def test_check_safety_safe_file(self):
        """Test --check-safety on a safe pickle file."""
        result = main(["fickling", "--check-safety", str(self.pickle_file)])
        self.assertEqual(result, 0)

    def test_help_flag(self):
        """Test --help flag."""
        with self.assertRaises(SystemExit) as cm:
            main(["fickling", "--help"])
        self.assertEqual(cm.exception.code, 0)


class TestCLISubcommandRouting(TestCase):
    """Test that subcommand routing works correctly."""

    def test_pytorch_subcommand_no_args(self):
        """Test 'fickling pytorch' with no arguments."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "pytorch"])
        self.assertEqual(result, 1)
        self.assertIn("pytorch subcommand required", stderr.getvalue())

    def test_polyglot_subcommand_no_args(self):
        """Test 'fickling polyglot' with no arguments."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "polyglot"])
        self.assertEqual(result, 1)
        self.assertIn("polyglot subcommand required", stderr.getvalue())


class TestPyTorchCLI(TestCase):
    """Test PyTorch CLI subcommands."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_pytorch_identify(self):
        """Test 'fickling pytorch identify'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "pytorch", "identify", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Detected format", output)
        self.assertIn("PyTorch", output)

    def test_pytorch_identify_json(self):
        """Test 'fickling pytorch identify --json'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "pytorch", "identify", "--json", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should be valid JSON
        import json

        data = json.loads(output)
        self.assertIn("formats", data)
        self.assertIn("primary_format", data)

    def test_pytorch_show(self):
        """Test 'fickling pytorch show'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "pytorch", "show", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should contain decompiled code
        self.assertIn("result", output)

    def test_pytorch_check_safety(self):
        """Test 'fickling pytorch check-safety'."""
        result = main(["fickling", "pytorch", "check-safety", str(self.model_file)])
        # Result can be 0 (safe) or 1 (potentially unsafe) - just verify it runs
        self.assertIn(result, [0, 1])

    def test_pytorch_inject(self):
        """Test 'fickling pytorch inject'."""
        output_file = self.tmppath / "injected.pth"
        result = main(
            [
                "fickling",
                "pytorch",
                "inject",
                str(self.model_file),
                "-o",
                str(output_file),
                "-c",
                "print('test')",
            ]
        )
        self.assertEqual(result, 0)
        self.assertTrue(output_file.exists())

    def test_pytorch_inject_combination_method(self):
        """Test 'fickling pytorch inject --method combination'."""
        output_file = self.tmppath / "injected_combo.pth"
        result = main(
            [
                "fickling",
                "pytorch",
                "inject",
                str(self.model_file),
                "-o",
                str(output_file),
                "-c",
                "print('test')",
                "--method",
                "combination",
            ]
        )
        self.assertEqual(result, 0)
        self.assertTrue(output_file.exists())

    def test_pytorch_file_not_found(self):
        """Test PyTorch commands with non-existent file."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "pytorch", "identify", "/nonexistent/file.pth"])
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestPolyglotCLI(TestCase):
    """Test polyglot CLI subcommands."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a PyTorch model file
        model = models.mobilenet_v2(weights=None)
        self.model_file = self.tmppath / "model.pth"
        torch.save(model, self.model_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_polyglot_identify(self):
        """Test 'fickling polyglot identify'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "polyglot", "identify", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Identified format", output)

    def test_polyglot_identify_json(self):
        """Test 'fickling polyglot identify --json'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "polyglot", "identify", "--json", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should be valid JSON
        import json

        data = json.loads(output)
        self.assertIn("formats", data)
        self.assertIn("is_polyglot", data)

    def test_polyglot_properties(self):
        """Test 'fickling polyglot properties'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "polyglot", "properties", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("File properties", output)

    def test_polyglot_properties_json(self):
        """Test 'fickling polyglot properties --json'."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["fickling", "polyglot", "properties", "--json", str(self.model_file)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        # Should be valid JSON
        import json

        data = json.loads(output)
        self.assertIn("properties", data)

    def test_polyglot_file_not_found(self):
        """Test polyglot commands with non-existent file."""
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "polyglot", "identify", "/nonexistent/file.pth"])
        self.assertEqual(result, 1)
        self.assertIn("file not found", stderr.getvalue())


class TestCLIErrorHandling(TestCase):
    """Test CLI error handling."""

    def test_nonexistent_pickle_file(self):
        """Test decompiling non-existent file raises FileNotFoundError."""
        # The original CLI raises FileNotFoundError for non-existent files
        with self.assertRaises(FileNotFoundError):
            main(["fickling", "/nonexistent/file.pkl"])

    def test_pytorch_inject_missing_output(self):
        """Test pytorch inject without required --output flag."""
        with self.assertRaises(SystemExit):
            main(["fickling", "pytorch", "inject", "file.pth", "-c", "code"])

    def test_pytorch_inject_missing_code(self):
        """Test pytorch inject without required --code flag."""
        with self.assertRaises(SystemExit):
            main(["fickling", "pytorch", "inject", "file.pth", "-o", "out.pth"])
