from ast import unparse
from contextlib import redirect_stdout
from functools import wraps
from pathlib import Path
from pickle import dumps, loads
from tempfile import NamedTemporaryFile
from unittest import TestCase

from fickling import fickle as fpickle
from fickling.analysis import check_safety
from fickling.cli import main
from fickling.fickle import Interpreter, Pickled, StackedPickle


def get_result(pickled: Pickled):
    ast = pickled.ast
    global_vars = {}
    local_vars = {}
    code = unparse(ast)
    exec(code, global_vars, local_vars)
    return local_vars["result"]


def correctness_test(to_pickle):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            pickled = dumps(to_pickle)
            self.assertEqual(to_pickle, get_result(Pickled.load(pickled)))

        return wrapper

    return decorator


def stacked_correctness_test(*to_pickle):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            to_pickle_list = list(to_pickle)
            stacked = [dumps(p) for p in to_pickle_list]
            stacked_pickle = StackedPickle.load(b"".join(stacked))
            self.assertEqual(len(stacked_pickle), len(stacked))
            for pickled, p_bytes, original in zip(stacked_pickle, stacked, to_pickle_list):
                stacked_ast = pickled.ast
                true_ast = Pickled.load(p_bytes).ast
                stacked_code = unparse(stacked_ast)
                true_code = unparse(true_ast)
                self.assertEqual(stacked_code, true_code)
                global_vars = {}
                local_vars = {}
                exec(stacked_code, global_vars, local_vars)
                self.assertIn("result", local_vars)
                self.assertEqual(original, local_vars["result"])

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

    def test_call(self):
        pickled = Pickled(
            [
                fpickle.Global.create("builtins", "eval"),
                fpickle.Mark(),
                fpickle.Unicode("(lambda:1234)()"),
                fpickle.Tuple(),
                fpickle.Reduce(),
                fpickle.Stop(),
            ]
        )
        self.assertEqual(1234, get_result(pickled))

    def test_inst(self):
        pickled = Pickled(
            [
                fpickle.Mark(),
                fpickle.Unicode("1234"),
                fpickle.Inst.create("builtins", "int"),
                fpickle.Stop(),
            ]
        )
        self.assertEqual(1234, get_result(pickled))

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

    def test_insert_list_arg(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python(
            [1, 2, ["a", "b"], 3],
            module="builtins",
            attr="tuple",
            use_output_as_unpickle_result=True,
            run_first=False,
        )
        self.assertIsInstance(loaded[-1], fpickle.Stop)

        # Make sure the injected code cleans up the stack after itself:
        interpreter = Interpreter(loaded)
        interpreter.run()
        self.assertEqual(len(interpreter.stack), 0)

        # Make sure the output is correct
        evaluated = loads(loaded.dumps())
        self.assertEqual((1, 2, ["a", "b"], 3), evaluated)

    def test_insert_run_last(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval(
            "[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=False
        )
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
        loaded.insert_python_eval(
            "[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=True
        )
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        evaluated = loads(loaded.dumps())
        self.assertEqual([5, 6, 7, 8], evaluated)

    def test_unused_variables(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        self.assertIsInstance(loaded[-1], fpickle.Stop)
        loaded.insert_python_eval(
            "[5, 6, 7, 8]", run_first=False, use_output_as_unpickle_result=True
        )
        interpreter = Interpreter(loaded)
        unused = interpreter.unused_variables()
        self.assertEqual(len(unused), 1)
        self.assertIn("_var0", unused)
        test_unused_variables_results = check_safety(loaded).to_dict()
        self.assertEqual(test_unused_variables_results["severity"], "OVERTLY_MALICIOUS")

    @stacked_correctness_test([1, 2, 3, 4], [5, 6, 7, 8])
    def test_stacked_pickles(self):
        pass

    def test_insert_stacked(self):
        tmpfile = NamedTemporaryFile("wb", delete=False)
        try:
            tmpfile.write(dumps([1, 2, 3, 4]))
            tmpfile.write(dumps(["a", "b", "c", "d"]))
            tmpfile.write(dumps(1234567))
            tmpfile.close()

            # Ensure it fails if we try and inject into the fourth stacked pickle (there are only 3)
            self.assertNotEqual(
                main(["", tmpfile.name, "--inject", 'print("foo")', "--inject-target", "3"]), 0
            )

            # Inject into the second pickle (this should work)
            try:
                with NamedTemporaryFile("wb", delete=False) as outfile, redirect_stdout(outfile):
                    retval = main(
                        [
                            "",
                            tmpfile.name,
                            "--inject",
                            "(lambda:7654321)()",
                            "--inject-target",
                            "1",
                            "--replace-result",
                        ]
                    )
                    self.assertEqual(retval, 0)
                    outfile.close()
                with open(outfile.name, "rb") as f:
                    stacked = StackedPickle.load(f)
            finally:
                Path(outfile.name).unlink()

            self.assertEqual(len(stacked), 3)
            self.assertEqual(7654321, get_result(stacked[1]))

        finally:
            Path(tmpfile.name).unlink()

    def test_duplicate_proto(self):
        pickled = dumps([1, 2, 3, 4])
        loaded = Pickled.load(pickled)
        test_duplicate_proto_one_results = check_safety(loaded).to_dict()
        print(test_duplicate_proto_one_results)
        self.assertEqual(test_duplicate_proto_one_results["severity"], "LIKELY_SAFE")
        loaded.insert(-1, fpickle.Proto.create(1))
        loaded.insert(-1, fpickle.Proto.create(2))
        test_duplicate_proto_two_results = check_safety(loaded).to_dict()
        self.assertEqual(test_duplicate_proto_two_results["severity"], "LIKELY_UNSAFE")

    def test_ext1(self):
        """Test EXT1 opcode (1-byte extension code)."""
        import copyreg
        import io
        from collections import OrderedDict

        # Register extension for test
        copyreg.add_extension("collections", "OrderedDict", 42)
        try:
            # Build raw pickle bytes: PROTO 2, EXT1(42), EMPTY_TUPLE, REDUCE, STOP
            pickle_bytes = bytes(
                [
                    0x80,
                    0x02,  # PROTO 2
                    0x82,
                    42,  # EXT1 with code 42
                    0x29,  # EMPTY_TUPLE
                    0x52,  # REDUCE
                    0x2E,  # STOP
                ]
            )
            pickled = Pickled.load(io.BytesIO(pickle_bytes))
            result = get_result(pickled)
            self.assertIsInstance(result, OrderedDict)
            self.assertEqual(result, OrderedDict())

            # Compare with real pickle
            real_result = loads(pickle_bytes)
            self.assertEqual(type(result), type(real_result))
        finally:
            copyreg.remove_extension("collections", "OrderedDict", 42)

    def test_ext2(self):
        """Test EXT2 opcode (2-byte extension code)."""
        import copyreg
        import io
        import struct
        from collections import Counter

        # Register extension with code > 255 (requires EXT2)
        copyreg.add_extension("collections", "Counter", 1000)
        try:
            # Build raw pickle bytes: PROTO 2, EXT2(1000), EMPTY_TUPLE, REDUCE, STOP
            pickle_bytes = (
                bytes([0x80, 0x02, 0x83])  # PROTO 2, EXT2
                + struct.pack("<H", 1000)  # 1000 as 2-byte little-endian
                + bytes([0x29, 0x52, 0x2E])  # EMPTY_TUPLE, REDUCE, STOP
            )
            pickled = Pickled.load(io.BytesIO(pickle_bytes))
            result = get_result(pickled)
            self.assertIsInstance(result, Counter)
            self.assertEqual(result, Counter())

            # Compare with real pickle
            real_result = loads(pickle_bytes)
            self.assertEqual(type(result), type(real_result))
        finally:
            copyreg.remove_extension("collections", "Counter", 1000)

    def test_ext4(self):
        """Test EXT4 opcode (4-byte extension code)."""
        import copyreg
        import io
        import struct
        from collections import deque

        # Register extension with code > 65535 (requires EXT4)
        copyreg.add_extension("collections", "deque", 100000)
        try:
            # Build raw pickle bytes: PROTO 2, EXT4(100000), EMPTY_TUPLE, REDUCE, STOP
            pickle_bytes = (
                bytes([0x80, 0x02, 0x84])  # PROTO 2, EXT4
                + struct.pack("<I", 100000)  # 100000 as 4-byte little-endian
                + bytes([0x29, 0x52, 0x2E])  # EMPTY_TUPLE, REDUCE, STOP
            )
            pickled = Pickled.load(io.BytesIO(pickle_bytes))
            result = get_result(pickled)
            self.assertIsInstance(result, deque)
            self.assertEqual(result, deque())

            # Compare with real pickle
            real_result = loads(pickle_bytes)
            self.assertEqual(type(result), type(real_result))
        finally:
            copyreg.remove_extension("collections", "deque", 100000)

    def test_ext_with_function(self):
        """Test EXT opcode with a function (not just classes)."""
        import copyreg
        import io
        import os.path

        # Register a function as extension
        copyreg.add_extension("os.path", "join", 200)
        try:
            # Build raw pickle bytes:
            # PROTO 2, EXT1(200), SHORT_BINUNICODE("/home"),
            # SHORT_BINUNICODE("user"), TUPLE2, REDUCE, STOP
            pickle_bytes = bytes(
                [
                    0x80,
                    0x02,  # PROTO 2
                    0x82,
                    200,  # EXT1 with code 200
                    0x8C,
                    5,
                    ord("/"),
                    ord("h"),
                    ord("o"),
                    ord("m"),
                    ord("e"),  # SHORT_BINUNICODE "/home"
                    0x8C,
                    4,
                    ord("u"),
                    ord("s"),
                    ord("e"),
                    ord("r"),  # SHORT_BINUNICODE "user"
                    0x86,  # TUPLE2 (creates tuple from top 2 stack items)
                    0x52,  # REDUCE
                    0x2E,  # STOP
                ]
            )
            pickled = Pickled.load(io.BytesIO(pickle_bytes))
            result = get_result(pickled)
            self.assertEqual(result, os.path.join("/home", "user"))

            # Compare with real pickle
            real_result = loads(pickle_bytes)
            self.assertEqual(result, real_result)
        finally:
            copyreg.remove_extension("os.path", "join", 200)
