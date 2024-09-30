import os
import pickle
import unittest
from pickle import UnpicklingError

import numpy
import torch

import fickling.hook as hook
from fickling.exception import UnsafeFileError

# Simple payload for tests
class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))

class OuterPayload:
    def __init__(self, data):
        self.data = data
    
    def __reduce__(self): 
        return (pickle.loads, (self.data,))


class TestUnpickler(unittest.TestCase):
    def setUp(self):
        # Create bad pickle files before hooking the pickle module because the 
        # nested bad file uses the pickle functions.
        with open("simple_unsafe.pickle", "wb") as f:
            pickle.dump(Payload(), f)
        with open("nested_unsafe.pickle", "wb") as f:
            inner = pickle.dumps(Payload())
            pickle.dump(OuterPayload(inner), f)
        with open("allowed_unsafe.pickle", "wb") as f:
            inner = pickle.dumps(numpy.dtype(">i4"))
            pickle.dump(OuterPayload(inner), f)

        # Set up global fickling hook using unpickler
        hook.restrict_to_ml_models(also_allow=["pickle.loads", "_pickle.loads"])

    def tearDown(self):
        # Remove fickling hooks
        hook.remove_hook()
        # Clean up files
        for filename in ["simple_unsafe.pickle", "nested_unsafe.pickle", "allowed_unsafe.pickle"]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_safe_pickle(self):
        # Fickling can check a pickle file for safety prior to running it
        test_list = [1, 2, 3]

        # Create "safe" pickle file
        with open("safe.pkl", "wb") as file:
            pickle.dump(test_list, file)

        # Load the safe pickle file
        with open("safe.pkl", "rb") as file:
            loaded_data = pickle.load(file)

        if os.path.exists("safe.pkl"):
            os.remove("safe.pkl")

        # Assert that the loaded data matches the original data
        self.assertEqual(loaded_data, test_list)

    def test_simple_unsafe_pickle(self):
        try:
            with open("simple_unsafe.pickle", "rb") as f:
                pickle.load(f)
                self.fail("Didn't detect unsafe pickle")
        except Exception as e:
            if isinstance(e, UnsafeFileError):
                pass
            else:
                self.fail(e)

    def test_nested_unsafe_pickle(self):
        """This makes sure it catches malicious code in a pickle-inside-pickle situation"""
        try:
            with open("nested_unsafe.pickle", "rb") as f:
                pickle.load(f)
                self.fail("Didn't detect unsafe pickle")
        except Exception as e:
            if isinstance(e, UnsafeFileError):
                pass
            else:
                self.fail(e)

    def test_allowed_unsafe_pickle(self):
        """This checks whether allowing additional imports works in the custom Unpickler"""

        with open("allowed_unsafe.pickle", "rb") as f:
            a = pickle.load(f)

        # Assert that the loaded data matches the original data
        self.assertIsInstance(a, numpy.dtype)
