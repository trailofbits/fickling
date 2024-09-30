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
    def __init__(self):
        self.b = 2
    
    def __reduce__(self): 
        return (pickle.loads, (pickle.dumps(Payload()),))


class TestUnpickler(unittest.TestCase):
    def setUp(self):
        # Set up global fickling hook using unpickler
        hook.restrict_to_ml_models()

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
        payload = Payload()

        # Save the payload in a pickle file
        with open("unsafe.pickle", "wb") as f:
            pickle.dump(payload, f)

        try:
            with open("unsafe.pickle", "rb") as f:
                pickle.load(f)
                self.fail("Didn't detect unsafe pickle")
        except Exception as e:
            if isinstance(e, UnsafeFileError):
                pass
            else:
                self.fail(e)

        if os.path.exists("unsafe.pickle"):
            os.remove("unsafe.pickle")

    def test_nested_unsafe_pickle(self):
        """This makes sure it catches malicious code in a pickle-inside-pickle situation"""

        # Save the payload in a pickle file
        with open("unsafe.pickle", "wb") as f:
            pickle.dump(OuterPayload(), f)

        try:
            with open("unsafe.pickle", "rb") as f:
                pickle.load(f)
                self.fail("Didn't detect unsafe pickle")
        except Exception as e:
            if isinstance(e, UnsafeFileError):
                pass
            else:
                self.fail(e)

        if os.path.exists("unsafe.pickle"):
            os.remove("unsafe.pickle")