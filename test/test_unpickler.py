import io
import pickle
import unittest

import numpy
import torch

from fickling import hook
from fickling.exception import UnsafeFileError
from fickling.ml import ML_ALLOWLIST, FicklingMLUnpickler


# Simple payload for tests
class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        import os

        return (os.system, ("echo 'I should have been stopped by the hook'",))


class OuterPayload:
    """Payload to execute arbitrary pickle payload through pickle.loads"""

    def __init__(self, data):
        self.data = data

    def __reduce__(self):
        return (pickle.loads, (self.data,))


class Bypass:
    """Payload to execute arbitrary pickle payload through torch.storage_load_from_bytes"""

    def __init__(self, data):
        self.data = data

    def __reduce__(self):
        return (torch.storage._load_from_bytes, (self.data,))


class TestNestedUnpicklers(unittest.TestCase):
    def test_standalone_rejects_nested_unpickler(self):
        data = pickle.dumps(torch.storage._load_from_bytes)
        with self.assertRaises(UnsafeFileError):
            FicklingMLUnpickler(io.BytesIO(data)).load()

    def test_hook_nested_unpickler_option(self):
        helper = torch.storage._load_from_bytes
        data = pickle.dumps(helper)
        self.addCleanup(hook.restore_entry_points, hook.snapshot_entry_points())
        loaders = {
            "load": lambda: pickle.load(io.BytesIO(data)),
            "loads": lambda: pickle.loads(data),
            "Unpickler": lambda: pickle.Unpickler(io.BytesIO(data)).load(),
        }

        hook.activate_safe_ml_environment()
        for name, load in loaders.items():
            with self.subTest(entry_point=name, policy="default"):
                self.assertIs(load(), helper)

        hook.activate_safe_ml_environment(allow_nested_unpicklers=False)
        for name, load in loaders.items():
            with (
                self.subTest(entry_point=name, policy="disabled"),
                self.assertRaises(UnsafeFileError),
            ):
                load()


class TestUnpickler(unittest.TestCase):
    def setUp(self):
        # Create bad pickle bytes before hooking the pickle module because the
        # nested bad file uses the pickle functions.
        self.simple_unsafe_bytes = pickle.dumps(Payload())

        inner = pickle.dumps(Payload())
        self.nested_unsafe_bytes = pickle.dumps(OuterPayload(pickle.dumps(Bypass(inner))))

        inner = pickle.dumps(numpy.dtype(">i4"))
        self.allowed_unsafe_bytes = pickle.dumps(OuterPayload(inner))

        # Set up global fickling hook using unpickler
        hook.activate_safe_ml_environment(also_allow=["pickle.loads", "_pickle.loads"])

    def tearDown(self):
        # Remove fickling hooks
        hook.remove_hook()

    def test_safe_pickle(self):
        # Fickling can check a pickle file for safety prior to running it
        test_list = [1, 2, 3]
        data = pickle.dumps(test_list)
        loaded_data = pickle.load(io.BytesIO(data))
        self.assertEqual(loaded_data, test_list)

    def test_simple_unsafe_pickle(self):
        with self.assertRaises(UnsafeFileError):
            pickle.load(io.BytesIO(self.simple_unsafe_bytes))

    def test_nested_unsafe_pickle(self):
        """This makes sure it catches malicious code in a pickle-inside-pickle situation"""
        with self.assertRaises(UnsafeFileError):
            pickle.load(io.BytesIO(self.nested_unsafe_bytes))

    def test_allowed_unsafe_pickle(self):
        """This checks whether allowing additional imports works in the custom Unpickler"""
        a = pickle.load(io.BytesIO(self.allowed_unsafe_bytes))
        self.assertIsInstance(a, numpy.dtype)


class TestMLUnpicklerAllowlistIsolation(unittest.TestCase):
    def test_also_allow_does_not_mutate_global_allowlist(self):
        """Regression test for #355: `also_allow` must not leak into ML_ALLOWLIST."""
        before = {module: dict(names) for module, names in ML_ALLOWLIST.items()}
        FicklingMLUnpickler(io.BytesIO(b""), also_allow=["collections.Counter"])
        self.assertEqual(ML_ALLOWLIST, before)
        self.assertNotIn("Counter", ML_ALLOWLIST.get("collections", {}))

def test_also_allow_is_isolated_between_unpicklers(self):
    """An `also_allow` entry on one unpickler must not be visible to another."""
    first = FicklingMLUnpickler(io.BytesIO(b""), also_allow=["collections.Counter"])
    self.assertIn("Counter", first.allowlist.get("collections", {}))
    self.assertIsNot(first.allowlist["collections"], ML_ALLOWLIST["collections"])
    second = FicklingMLUnpickler(io.BytesIO(b""))
    self.assertNotIn("Counter", second.allowlist.get("collections", {}))
    self.assertNotIn("Counter", ML_ALLOWLIST.get("collections", {}))
