import os
import pickle
import unittest
from pickle import UnpicklingError

import numpy

import fickling.hook as hook
from fickling.exception import UnsafeFileError


class TestHook(unittest.TestCase):
    def setUp(self):
        # Set up global fickling hook
        hook.run_hook()

    def test_safe_pickle(self):
        # Fickling can check a pickle file for safety prior to running it
        test_list = [1, 2, 3]

        # Create "safe" pickle file
        with open("safe.pkl", "wb") as file:
            pickle.dump(test_list, file)

        # Load the safe pickle file
        with open("safe.pkl", "rb") as file:
            loaded_data = pickle.load(file)

        # Assert that the loaded data matches the original data
        self.assertEqual(loaded_data, test_list)

    def test_unsafe_pickle(self):
        # Create "unsafe" pickle file
        class Payload:
            def __init__(self):
                self.a = 1

            def __reduce__(self):
                return (os.system, ("echo 'I should have been stopped by the hook'",))

        payload = Payload()
        # Validate that pty-based execution is captured
        payload_pty = b'''(cpty\nspawn\nS"id"\no.'''


        # Save the payload in a pickle file
        with open("unsafe.pickle", "wb") as f:
            pickle.dump(payload, f)
        with open("unsafe_pty.pickle", "wb") as f:
            f.write(payload_pty)

        for f in ["unsafe.pickle", "unsafe_pty.pickle"]:
            try:
                numpy.load(f, allow_pickle=True)
            except UnpicklingError as e:
                if isinstance(e.__cause__, UnsafeFileError):
                    pass
                else:
                    self.fail(e)
