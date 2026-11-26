import _pickle
import importlib.util
import io
import pickle
import types
import unittest
import warnings
from pickle import UnpicklingError
from unittest.mock import Mock, patch

import numpy

import fickling
from fickling import hook
from fickling.exception import UnsafeFileError


# Simple payload for tests
class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        import os

        return (os.system, ("echo 'I should have been stopped by the hook'",))


class TestHook(unittest.TestCase):
    def setUp(self):
        # Set up global fickling hook
        hook.run_hook()

    def tearDown(self):
        hook.remove_hook()

    def test_safe_pickle(self):
        # Fickling can check a pickle file for safety prior to running it
        test_list = [1, 2, 3]
        data = pickle.dumps(test_list)
        loaded_data = pickle.load(io.BytesIO(data))
        self.assertEqual(loaded_data, test_list)

    def test_unsafe_pickle(self):
        # Create "unsafe" pickle bytes
        payload = Payload()
        data = pickle.dumps(payload)

        try:
            numpy.load(io.BytesIO(data), allow_pickle=True)
        except UnpicklingError as e:
            if isinstance(e.__cause__, UnsafeFileError):
                pass
            else:
                self.fail(e)

    # https://github.com/trailofbits/fickling/security/advisories/GHSA-wccx-j62j-r448
    # https://github.com/trailofbits/fickling/security/advisories/GHSA-fphw-536r-4p88
    def test_run_hook_covers_all_entry_points(self):
        data = pickle.dumps(Payload())
        cases = {
            "pickle.load": lambda: pickle.load(io.BytesIO(data)),
            "pickle.loads": lambda: pickle.loads(data),
            "pickle.Unpickler": lambda: pickle.Unpickler(io.BytesIO(data)).load(),
            "pickle._load": lambda: pickle._load(io.BytesIO(data)),
            "pickle._loads": lambda: pickle._loads(data),
            "pickle._Unpickler": lambda: pickle._Unpickler(io.BytesIO(data)).load(),
            "_pickle.load": lambda: _pickle.load(io.BytesIO(data)),
            "_pickle.loads": lambda: _pickle.loads(data),
            "_pickle.Unpickler": lambda: _pickle.Unpickler(io.BytesIO(data)).load(),
        }
        for name, call in cases.items():
            with (
                self.subTest(entry_point=name),
                self.assertRaises(UnsafeFileError, msg=f"{name} was not intercepted"),
            ):
                call()


_CONSUMER_NAME = "fickling_test_early_importer"
_INDIRECT_CONSUMER_NAME = "fickling_test_indirect_importer"


class TestStaleReferenceWarning(unittest.TestCase):
    def setUp(self):
        # Order matters: the consumer resolves its names before the hook is installed, and it
        # lives in sys.modules like any real dependency would.
        self.consumer = types.ModuleType(_CONSUMER_NAME)
        self.consumer.Unpickler = pickle.Unpickler
        self.consumer.load = pickle.load
        self.consumer.loads = pickle.loads
        self.modules = {_CONSUMER_NAME: self.consumer, "pickle": pickle, "_pickle": _pickle}
        self.enterContext(patch.object(hook, "sys", types.SimpleNamespace(modules=self.modules)))
        self.addCleanup(hook.remove_hook)

    def test_hooks_skip_scan_by_default(self):
        with patch.object(hook, "_find_stale_references") as scan:
            hook.run_hook()
            hook.activate_safe_ml_environment()
            with fickling.check_safety():
                pass
            scan.assert_not_called()

    def test_warn_about_stale_pickle_references(self):
        expected = [f"{_CONSUMER_NAME}.{attr}" for attr in ("Unpickler", "load", "loads")]
        for install in (fickling.always_check_safety, fickling.activate_safe_ml_environment):
            with self.subTest(install=install.__name__):
                with self.assertWarns(hook.StalePickleReferenceWarning) as caught:
                    install(warn_on_stale_references=True)
                self.assertIn(", ".join(expected), str(caught.warning))
                self.assertEqual(caught.filename, __file__)
                self.assertIsNot(pickle.load, self.consumer.load)
                hook.remove_hook()

    def test_warning_summarizes_long_lists(self):
        expected = [f"consumer.reader_{i:02d}" for i in range(12)]
        with (
            patch.object(hook, "_find_stale_references", return_value=expected),
            self.assertWarns(hook.StalePickleReferenceWarning) as caught,
        ):
            hook.run_hook(warn_on_stale_references=True)
        message = str(caught.warning)
        self.assertIn(f"{', '.join(expected[:10])}, and 2 more", message)
        for omitted in expected[10:]:
            self.assertNotIn(omitted, message)

    def test_indirect_entry_points_are_not_reported(self):
        # pickle._load/_loads resolve _Unpickler from pickle's globals when called, so a stale
        # reference to one still reaches the patched unpickler.
        indirect = types.ModuleType(_INDIRECT_CONSUMER_NAME)
        indirect._load = pickle._load
        indirect._loads = pickle._loads
        self.modules[_INDIRECT_CONSUMER_NAME] = indirect

        with self.assertWarns(hook.StalePickleReferenceWarning) as caught:
            hook.run_hook(warn_on_stale_references=True)
        self.assertNotIn(_INDIRECT_CONSUMER_NAME, str(caught.warning))

        # ...and the reference really is still safe to call.
        with self.assertRaises(UnsafeFileError):
            indirect._load(io.BytesIO(pickle.dumps(Payload())))

    def test_warning_as_error_preserves_active_hook(self):
        hook.activate_safe_ml_environment()
        active = hook.snapshot_entry_points()
        with warnings.catch_warnings():
            warnings.simplefilter("error", hook.StalePickleReferenceWarning)
            with self.assertRaises(hook.StalePickleReferenceWarning):
                hook.run_hook(warn_on_stale_references=True)
            self.assertEqual(hook.snapshot_entry_points(), active)
            with (
                self.assertRaises(hook.StalePickleReferenceWarning),
                fickling.check_safety(warn_on_stale_references=True),
            ):
                self.fail("The warning should be raised on context entry")
            self.assertEqual(hook.snapshot_entry_points(), active)

    def test_module_without_stale_reference_is_not_reported(self):
        del self.modules[_CONSUMER_NAME]
        with warnings.catch_warnings():
            warnings.simplefilter("error", hook.StalePickleReferenceWarning)
            hook.run_hook(warn_on_stale_references=True)

    def test_scan_leaves_lazy_module_uninitialized(self):
        loader = Mock()
        module = types.ModuleType("lazy_consumer")
        module.__spec__ = importlib.util.spec_from_loader(module.__name__, loader, is_package=False)
        self.modules[module.__name__] = module
        importlib.util.LazyLoader(loader).exec_module(module)

        with self.assertWarns(hook.StalePickleReferenceWarning):
            hook.run_hook(warn_on_stale_references=True)
        loader.exec_module.assert_not_called()
