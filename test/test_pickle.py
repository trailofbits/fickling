from functools import wraps
from pickle import dumps, loads
from sys import version_info
from unittest import TestCase

if version_info >= (3, 9):
    from ast import unparse
else:
    from astunparse import unparse

from fickling import pickle as fpickle
from fickling.pickle import Pickled, Interpreter
from fickling.analysis import check_safety


def correctness_test(to_pickle):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            pickled = dumps(to_pickle)
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

    def test_dumps(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertEqual(pickled, loaded.dumps())

    def test_insert(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval("[5, 6, 7, 8]", use_output_as_unpickle_result=True)
        self.assertIsInstance(loaded[-1], fpickle.Stop)

        # Make sure the injected code cleans up the stack after itself:
        interpreter = Interpreter(loaded)
        interpreter.run()
        self.assertEqual(len(interpreter.stack), 0)

        # Make sure the output is correct
        evaluated = loads(loaded.dumps())
        self.assertEqual([5, 6, 7, 8], evaluated)

    def test_insert_run_last(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval("[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=False)
        self.assertEqual(sum(1 for op in loaded if isinstance(op, fpickle.Stop)), 1)
        self.assertIsInstance(loaded[-1], fpickle.Stop)

        # Make sure the injected code cleans up the stack after itself:
        interpreter = Interpreter(loaded)
        interpreter.run()
        self.assertEqual(len(interpreter.stack), 0)

        # Make sure the output is correct
        evaluated = loads(loaded.dumps())
        self.assertEqual([1, 2, 3, 4], evaluated)

    def test_insert_run_last_replace_output(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval("[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=True)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        evaluated = loads(loaded.dumps())
        self.assertEqual([5, 6, 7, 8], evaluated)

    def test_unused_variables(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval("[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=True)
        interpreter = Interpreter(loaded)
        unused = interpreter.unused_variables()
        self.assertEqual(len(unused), 1)
        self.assertIn("_var0", unused)
        self.assertFalse(check_safety(loaded))
