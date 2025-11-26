import os
import pickle
import unittest

import fickling
from fickling.exception import UnsafeFileError


class Payload:
    """Malicious payload for testing"""
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'malicious code'",))


class TestLoadsAPI(unittest.TestCase):
    """Test the fickling.loads() public API function"""

    def test_loads_safe_data(self):
        """Test that fickling.loads() works with safe pickle data"""
        test_list = [1, 2, 3, {"key": "value"}]

        # Create pickle bytes
        data = pickle.dumps(test_list)

        # Load using fickling.loads()
        loaded_data = fickling.loads(data)

        # Assert that the loaded data matches the original
        self.assertEqual(loaded_data, test_list)

    def test_loads_unsafe_data(self):
        """Test that fickling.loads() rejects unsafe pickle data"""
        payload = Payload()

        # Create unsafe pickle bytes
        data = pickle.dumps(payload)

        # Should raise UnsafeFileError
        with self.assertRaises(UnsafeFileError):
            fickling.loads(data)

    def test_loads_matches_pickle_signature(self):
        """Test that fickling.loads() accepts the same arguments as pickle.loads()"""
        test_data = {"a": 1, "b": 2}

        # Create pickle with protocol 2
        data = pickle.dumps(test_data, protocol=2)

        # Should work with extra args like pickle.loads()
        loaded_data = fickling.loads(data, encoding='ASCII', errors='strict')

        self.assertEqual(loaded_data, test_data)

    def test_loads_with_custom_severity(self):
        """Test that fickling.loads() respects custom severity levels"""
        from fickling.analysis import Severity

        test_list = [1, 2, 3]
        data = pickle.dumps(test_list)

        # Should work with different severity levels
        loaded_data = fickling.loads(data, max_acceptable_severity=Severity.POSSIBLY_UNSAFE)
        self.assertEqual(loaded_data, test_list)
