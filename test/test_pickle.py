from functools import wraps
from io import BytesIO
from pickle import dump
from unittest import TestCase

from astunparse import unparse

from fickling.pickle import Pickled


def correctness_test(to_pickle):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            b = BytesIO()
            dump(to_pickle, b)
            pickled = b.getvalue()
            ast = Pickled.load(pickled).ast
            global_vars = {}
            local_vars = {}
            code = unparse(ast)
            exec(code, global_vars, local_vars)
            self.assertIn("result", local_vars)
            self.assertEqual(to_pickle, local_vars["result"])

        return wrapper
    return decorator


class TestInterpreter(TestCase):
    @correctness_test(1337)
    def test_int(self):
        pass

    @correctness_test([1, 2, 3, 4, 5])
    def test_lists(self):
        pass

    @correctness_test((1, 2, 3, 4, 5))
    def test_tuples(self):
        pass

    @correctness_test({"a": 1, "b": 2})
    def test_dicts(self):
        pass

    @correctness_test("abcdefg")
    def test_strings(self):
        pass

    @correctness_test(b"abcdefg")
    def test_bytes(self):
        pass
