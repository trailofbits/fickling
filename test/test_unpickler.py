import io
import pickle
import unittest

import numpy
import torch

import fickling.hook as hook
from fickling.exception import UnsafeFileError


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
