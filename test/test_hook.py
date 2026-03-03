import _pickle
import io
import pickle
import unittest
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
    def test_run_hook_covers_all_entry_points(self):
        data = pickle.dumps(Payload())
        cases = {
            "pickle.load": lambda: pickle.load(io.BytesIO(data)),
            "pickle.loads": lambda: pickle.loads(data),
            "pickle.Unpickler": lambda: pickle.Unpickler(io.BytesIO(data)).load(),
            "_pickle.load": lambda: _pickle.load(io.BytesIO(data)),
            "_pickle.loads": lambda: _pickle.loads(data),
            "_pickle.Unpickler": lambda: _pickle.Unpickler(io.BytesIO(data)).load(),
        }
        for name, call in cases.items():
            with self.subTest(entry_point=name):
                with self.assertRaises(UnsafeFileError, msg=f"{name} was not intercepted"):
                    call()
