"""Missing/unwritable files must exit cleanly with EXIT_ERROR, not a traceback."""

import io
from contextlib import redirect_stderr
from unittest import TestCase

from fickling.cli import main
from fickling.constants import EXIT_ERROR


class TestCliMissingFile(TestCase):
    def test_missing_input_file_returns_exit_error(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "does-not-exist.pkl", "--check-safety"])
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("does-not-exist.pkl", stderr.getvalue())

    def test_unwritable_create_target_returns_exit_error(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["fickling", "no-such-dir/out.pkl", "--create", "x"])
        self.assertEqual(result, EXIT_ERROR)
        self.assertIn("no-such-dir/out.pkl", stderr.getvalue())
