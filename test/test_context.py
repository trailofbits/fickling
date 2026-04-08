import _pickle
import io
import pickle
import unittest

import fickling
import fickling.hook as hook
from fickling.analysis import Severity
from fickling.context import FicklingContextManager
from fickling.exception import UnsafeFileError

SAFE_DATA = pickle.dumps([1, 2, 3])

_MODULES = {"pickle": pickle, "_pickle": _pickle}


def _get_entry_point(name):
    mod_name, attr = name.split(".", 1)
    return getattr(_MODULES[mod_name], attr)


class UnsafePayload:
    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


UNSAFE_DATA = pickle.dumps(UnsafePayload())


class TestContextManagerHookLifecycle(unittest.TestCase):
    """Test that __enter__ activates hooks and __exit__ fully removes them."""

    def test_hooks_active_inside_context(self):
        with FicklingContextManager():
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

    def test_all_six_entry_points_hooked(self):
        """All 6 entry points must be intercepted inside the context."""
        cases = {
            "pickle.load": lambda: pickle.load(io.BytesIO(UNSAFE_DATA)),
            "pickle.loads": lambda: pickle.loads(UNSAFE_DATA),
            "pickle.Unpickler": lambda: pickle.Unpickler(io.BytesIO(UNSAFE_DATA)).load(),
            "_pickle.load": lambda: _pickle.load(io.BytesIO(UNSAFE_DATA)),
            "_pickle.loads": lambda: _pickle.loads(UNSAFE_DATA),
            "_pickle.Unpickler": lambda: _pickle.Unpickler(io.BytesIO(UNSAFE_DATA)).load(),
        }
        with FicklingContextManager():
            for name, call in cases.items():
                with self.subTest(entry_point=name):
                    with self.assertRaises(UnsafeFileError, msg=f"{name} not intercepted"):
                        call()

    def test_all_six_entry_points_restored_after_exit(self):
        """All 6 entry points must be restored to originals after exiting context."""
        originals = {
            "pickle.load": pickle.load,
            "pickle.loads": pickle.loads,
            "pickle.Unpickler": pickle.Unpickler,
            "_pickle.load": _pickle.load,
            "_pickle.loads": _pickle.loads,
            "_pickle.Unpickler": _pickle.Unpickler,
        }

        with FicklingContextManager():
            pass

        for name, original in originals.items():
            with self.subTest(entry_point=name):
                current = _get_entry_point(name)
                self.assertIs(current, original, f"{name} not restored after __exit__")

    def test_safe_pickle_passes_through(self):
        with FicklingContextManager():
            result = pickle.loads(SAFE_DATA)
            self.assertEqual(result, [1, 2, 3])

    def test_safe_pickle_via_load(self):
        with FicklingContextManager():
            result = pickle.load(io.BytesIO(SAFE_DATA))
            self.assertEqual(result, [1, 2, 3])


class TestContextManagerExceptionSafety(unittest.TestCase):
    """Test that hooks are cleaned up even when exceptions occur."""

    def test_hooks_restored_on_exception(self):
        originals = {
            "pickle.load": pickle.load,
            "pickle.loads": pickle.loads,
            "pickle.Unpickler": pickle.Unpickler,
            "_pickle.load": _pickle.load,
            "_pickle.loads": _pickle.loads,
            "_pickle.Unpickler": _pickle.Unpickler,
        }

        try:
            with FicklingContextManager():
                raise ValueError("test error")
        except ValueError:
            pass

        for name, original in originals.items():
            with self.subTest(entry_point=name):
                current = _get_entry_point(name)
                self.assertIs(current, original, f"{name} not restored after exception")

    def test_hooks_restored_on_unsafe_file_error(self):
        originals = {
            "pickle.load": pickle.load,
            "pickle.loads": pickle.loads,
        }

        try:
            with FicklingContextManager():
                pickle.loads(UNSAFE_DATA)
        except UnsafeFileError:
            pass

        for name, original in originals.items():
            with self.subTest(entry_point=name):
                current = _get_entry_point(name)
                self.assertIs(current, original, f"{name} not restored after UnsafeFileError")


class TestMaxAcceptableSeverity(unittest.TestCase):
    """Test that max_acceptable_severity is properly wired through."""

    def test_default_severity_is_likely_safe(self):
        cm = FicklingContextManager()
        self.assertEqual(cm.max_acceptable_severity, Severity.LIKELY_SAFE)

    def test_explicit_default_severity_passes_safe_pickle(self):
        """Explicitly passing LIKELY_SAFE (the default) still allows safe pickles."""
        with FicklingContextManager(max_acceptable_severity=Severity.LIKELY_SAFE):
            result = pickle.loads(SAFE_DATA)
            self.assertEqual(result, [1, 2, 3])

    def test_custom_severity_accepts_higher_threshold(self):
        """With a higher severity threshold, unsafe pickles may pass through."""
        with FicklingContextManager(max_acceptable_severity=Severity.OVERTLY_MALICIOUS):
            # Even overtly malicious payloads should pass when threshold is max
            result = pickle.loads(UNSAFE_DATA)
            # os.system("echo pwned") returns 0
            self.assertEqual(result, 0)

    def test_custom_severity_hooks_restored(self):
        """Custom severity hooks are cleaned up by remove_hook()."""
        originals = {
            "pickle.load": pickle.load,
            "pickle.loads": pickle.loads,
            "_pickle.load": _pickle.load,
            "_pickle.loads": _pickle.loads,
        }

        with FicklingContextManager(max_acceptable_severity=Severity.SUSPICIOUS):
            pass

        for name, original in originals.items():
            with self.subTest(entry_point=name):
                current = _get_entry_point(name)
                self.assertIs(current, original, f"{name} not restored after custom severity")


class TestCheckSafetyConvenience(unittest.TestCase):
    """Test the check_safety() convenience function."""

    def test_returns_context_manager(self):
        cm = fickling.check_safety()
        self.assertIsInstance(cm, FicklingContextManager)

    def test_usable_as_context_manager(self):
        with fickling.check_safety():
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

    def test_hooks_restored_after_convenience(self):
        original_loads = pickle.loads
        with fickling.check_safety():
            pass
        self.assertIs(pickle.loads, original_loads)


class TestContextManagerIdempotency(unittest.TestCase):
    """Test nesting and repeated use of the context manager."""

    def test_sequential_usage(self):
        for _ in range(3):
            with FicklingContextManager():
                with self.assertRaises(UnsafeFileError):
                    pickle.loads(UNSAFE_DATA)

        # After all contexts, originals are restored
        result = pickle.loads(SAFE_DATA)
        self.assertEqual(result, [1, 2, 3])

    def test_no_interaction_with_manual_hook(self):
        """Context manager should work independently of manual hook.run_hook()."""
        # Context manager on its own
        with FicklingContextManager():
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

        # Manual hook still works after
        hook.run_hook()
        try:
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)
        finally:
            hook.remove_hook()

    def test_preexisting_hook_survives_context_exit(self):
        """If run_hook() is active before context entry, it must remain active after exit."""
        hook.run_hook()
        try:
            # Hooks are active
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

            # Enter and exit context manager
            with FicklingContextManager():
                with self.assertRaises(UnsafeFileError):
                    pickle.loads(UNSAFE_DATA)

            # Pre-existing hooks must still be active after context exit
            with self.assertRaises(UnsafeFileError, msg="pre-existing hook was clobbered"):
                pickle.loads(UNSAFE_DATA)
        finally:
            hook.remove_hook()

    def test_preexisting_ml_hook_survives_context_exit(self):
        """If activate_safe_ml_environment() is active, context exit must preserve it."""
        hook.activate_safe_ml_environment()
        try:
            hooked_load = pickle.load
            hooked_loads = pickle.loads
            hooked_unpickler = pickle.Unpickler

            with FicklingContextManager():
                pass

            # ML hooks must still be in place
            self.assertIs(pickle.load, hooked_load, "ML hook on pickle.load was clobbered")
            self.assertIs(pickle.loads, hooked_loads, "ML hook on pickle.loads was clobbered")
            self.assertIs(
                pickle.Unpickler,
                hooked_unpickler,
                "ML hook on pickle.Unpickler was clobbered",
            )
        finally:
            hook.remove_hook()


class TestDuplicateKeywordSafety(unittest.TestCase):
    """Test that hooked functions don't raise TypeError from duplicate kwargs."""

    def test_explicit_severity_kwarg_does_not_raise(self):
        """Caller passing max_acceptable_severity should not cause TypeError."""
        with FicklingContextManager(max_acceptable_severity=Severity.SUSPICIOUS):
            # This would TypeError if the closure doesn't pop max_acceptable_severity
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA, max_acceptable_severity=Severity.LIKELY_SAFE)

    def test_unpickler_severity_kwarg_does_not_raise(self):
        """Unpickler path must also handle duplicate max_acceptable_severity."""
        with FicklingContextManager(max_acceptable_severity=Severity.SUSPICIOUS):
            with self.assertRaises(UnsafeFileError):
                pickle.Unpickler(
                    io.BytesIO(UNSAFE_DATA), max_acceptable_severity=Severity.LIKELY_SAFE
                ).load()


class TestReentrantUsage(unittest.TestCase):
    """Test that the same context manager instance can be nested safely."""

    def test_nested_same_instance_restores_correctly(self):
        """Nested reuse of the same CM instance must not leak hooks."""
        original_loads = pickle.loads
        cm = FicklingContextManager()

        with cm:
            with cm:
                with self.assertRaises(UnsafeFileError):
                    pickle.loads(UNSAFE_DATA)
            # Inner exit: hooks still active from outer enter
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

        # Outer exit: fully restored
        self.assertIs(pickle.loads, original_loads)

    def test_nested_different_severities(self):
        """Nested CMs with different severities restore correctly."""
        original_loads = pickle.loads

        with FicklingContextManager(max_acceptable_severity=Severity.LIKELY_SAFE):
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

            with FicklingContextManager(max_acceptable_severity=Severity.OVERTLY_MALICIOUS):
                # Inner context allows everything
                result = pickle.loads(UNSAFE_DATA)
                self.assertEqual(result, 0)

            # Outer context blocks again
            with self.assertRaises(UnsafeFileError):
                pickle.loads(UNSAFE_DATA)

        self.assertIs(pickle.loads, original_loads)
