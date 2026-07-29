import _pickle
import io
import pickle
import sys
import types
import unittest
import warnings
from pickle import UnpicklingError

import numpy

import fickling.hook as hook
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
            with self.subTest(entry_point=name):
                with self.assertRaises(UnsafeFileError, msg=f"{name} was not intercepted"):
                    call()


_CONSUMER_NAME = "fickling_test_early_importer"
_INDIRECT_CONSUMER_NAME = "fickling_test_indirect_importer"


class EarlyFromImportTestCase(unittest.TestCase):
    """Base for tests needing a module that from-imported pickle before the hook was installed"""

    def setUp(self):
        # Order matters: the consumer resolves its names before the hook is installed, and it
        # lives in sys.modules like any real dependency would.
        self.consumer = types.ModuleType(_CONSUMER_NAME)
        exec(
            "from pickle import Unpickler, load, loads\n"
            "def read_file(fp): return load(fp)\n"
            "def read_bytes(data): return loads(data)\n"
            "def read_unpickler(fp): return Unpickler(fp).load()\n",
            self.consumer.__dict__,
        )
        sys.modules[_CONSUMER_NAME] = self.consumer
        self.addCleanup(sys.modules.pop, _CONSUMER_NAME, None)
        self.addCleanup(hook.remove_hook)


class TestStaleReferenceWarning(EarlyFromImportTestCase):
    def test_run_hook_warns_about_stale_references(self):
        with self.assertWarns(hook.StalePickleReferenceWarning) as caught:
            hook.run_hook()
        message = str(caught.warning)
        for attr in ("load", "loads", "Unpickler"):
            with self.subTest(attr=attr):
                self.assertIn(f"{_CONSUMER_NAME}.{attr}", message)
        self.assertIn("cannot intercept these references", message)
        self.assertIn("Call run_hook() before importing anything that uses pickle.", message)

    def test_indirect_entry_points_are_not_reported(self):
        # pickle._load/_loads resolve _Unpickler from pickle's globals when called, so a stale
        # reference to one still reaches the patched unpickler.
        indirect = types.ModuleType(_INDIRECT_CONSUMER_NAME)
        exec("from pickle import _load, _loads", indirect.__dict__)
        sys.modules[_INDIRECT_CONSUMER_NAME] = indirect
        self.addCleanup(sys.modules.pop, _INDIRECT_CONSUMER_NAME, None)

        with self.assertWarns(hook.StalePickleReferenceWarning) as caught:
            hook.run_hook()
        self.assertNotIn(_INDIRECT_CONSUMER_NAME, str(caught.warning))

        # ...and the reference really is still safe to call.
        with self.assertRaises(UnsafeFileError):
            indirect._load(io.BytesIO(pickle.dumps(Payload())))

    def test_activate_safe_ml_environment_warns_too(self):
        with self.assertWarns(hook.StalePickleReferenceWarning) as caught:
            hook.activate_safe_ml_environment()
        self.assertIn(f"{_CONSUMER_NAME}.load", str(caught.warning))

    def test_module_without_stale_reference_is_not_reported(self):
        # Other test modules legitimately from-import pickle, so only assert on our consumer.
        sys.modules.pop(_CONSUMER_NAME)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            hook.run_hook()
        for warning in caught:
            if warning.category is hook.StalePickleReferenceWarning:
                self.assertNotIn(_CONSUMER_NAME, str(warning.message))


class TestHookWithEarlyFromImport(EarlyFromImportTestCase):
    """A consumer that from-imported pickle before run_hook() keeps the unpatched functions"""

    # Known gap: the hook rebinds pickle's namespace, which cannot reach references already
    # copied elsewhere. run_hook() only warns about these; see TestStaleReferenceWarning.
    @unittest.expectedFailure
    def test_early_from_import_is_still_hooked(self):
        hook.run_hook()
        data = pickle.dumps(Payload())
        cases = {
            "from pickle import load": lambda: self.consumer.read_file(io.BytesIO(data)),
            "from pickle import loads": lambda: self.consumer.read_bytes(data),
            "from pickle import Unpickler": lambda: self.consumer.read_unpickler(io.BytesIO(data)),
        }
        for name, call in cases.items():
            with self.assertRaises(UnsafeFileError, msg=f"{name} was not intercepted"):
                call()
