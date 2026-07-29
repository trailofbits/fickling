import _pickle
import io
import pickle
import unittest

import fickling
import fickling.hook as hook
from fickling.exception import UnsafeFileError


class Payload:
    def __reduce__(self):
        import os

        return (os.system, ("echo 'I should have been stopped'",))


class TestContextManager(unittest.TestCase):
    def setUp(self):
        self.entry_points = hook.snapshot_entry_points()

    def tearDown(self):
        hook.restore_entry_points(self.entry_points)

    def assert_entry_points_restored(self):
        for module, attr, original in self.entry_points:
            with self.subTest(entry_point=f"{module.__name__}.{attr}"):
                self.assertIs(getattr(module, attr), original)

    def test_all_entry_points_hooked(self):
        data = pickle.dumps(Payload())
        with fickling.check_safety():
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

    def test_all_entry_points_restored(self):
        with fickling.check_safety():
            pass
        self.assert_entry_points_restored()

    def test_entry_points_restored_on_exception(self):
        with self.assertRaises(UnsafeFileError):
            with fickling.check_safety():
                pickle.loads(pickle.dumps(Payload()))
        self.assert_entry_points_restored()

    def test_preexisting_hook_is_restored(self):
        hook.activate_safe_ml_environment()
        ml_entry_points = hook.snapshot_entry_points()
        with fickling.check_safety():
            pass
        for module, attr, ml_value in ml_entry_points:
            with self.subTest(entry_point=f"{module.__name__}.{attr}"):
                self.assertIs(getattr(module, attr), ml_value)

    def test_nested(self):
        with fickling.check_safety():
            outer = hook.snapshot_entry_points()
            with fickling.check_safety():
                pass
            for module, attr, outer_value in outer:
                with self.subTest(entry_point=f"{module.__name__}.{attr}"):
                    self.assertIs(getattr(module, attr), outer_value)
        self.assert_entry_points_restored()


if __name__ == "__main__":
    unittest.main()
