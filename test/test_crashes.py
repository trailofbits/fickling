"""
This test module checks against inputs that previously caused crashes
"""

import io
import pickle
from ast import unparse
from base64 import b64decode
from functools import wraps
from unittest import TestCase

from fickling.analysis import Severity, check_safety
from fickling.exception import ExpansionAttackError, ResourceExhaustionError
from fickling.fickle import (
    Append,
    BinGet,
    BinInt1,
    BinPut,
    BinUnicode,
    Dup,
    EmptyList,
    Global,
    Interpreter,
    InterpreterLimits,
    Mark,
    Memoize,
    Pickled,
    Pop,
    Proto,
    Reduce,
    ShortBinUnicode,
    StackGlobal,
    Stop,
    Tuple,
)


def unparse_test(pickled: bytes):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            ast = Pickled.load(pickled).ast
            _ = unparse(ast)

        return wrapper

    return decorator


class TestCrashes(TestCase):
    @unparse_test(
        b64decode(
            """gAJ9cQAoWA8AAABzdHJpbmdfdG9fdG9rZW5xAX1xAlgBAAAAKnEDY3RvcmNoLl91dGlscwpfcmVi
dWlsZF90ZW5zb3JfdjIKcQQoKFgHAAAAc3RvcmFnZXEFY3RvcmNoCkxvbmdTdG9yYWdlCnEGWAEA
AAAwcQdYAwAAAGNwdXEIS010cQlRSwEpKYljY29sbGVjdGlvbnMKT3JkZXJlZERpY3QKcQopUnEL
dHEMUnENc1gPAAAAc3RyaW5nX3RvX3BhcmFtcQ5jdG9yY2gubm4ubW9kdWxlcy5jb250YWluZXIK
UGFyYW1ldGVyRGljdApxDymBcRB9cREoWAgAAAB0cmFpbmluZ3ESiFgLAAAAX3BhcmFtZXRlcnNx
E2gKKVJxFGgDY3RvcmNoLl91dGlscwpfcmVidWlsZF9wYXJhbWV0ZXIKcRVoBCgoaAVjdG9yY2gK
RmxvYXRTdG9yYWdlCnEWWAEAAAAxcRdYBgAAAGN1ZGE6MHEYTQADdHEZUUsASwFNAAOGcRpNAANL
AYZxG4loCilScRx0cR1ScR6IaAopUnEfh3EgUnEhc1gIAAAAX2J1ZmZlcnNxImgKKVJxI1gbAAAA
X25vbl9wZXJzaXN0ZW50X2J1ZmZlcnNfc2V0cSRjX19idWlsdGluX18Kc2V0CnElXXEmhXEnUnEo
WA8AAABfYmFja3dhcmRfaG9va3NxKWgKKVJxKlgWAAAAX2lzX2Z1bGxfYmFja3dhcmRfaG9va3Er
TlgOAAAAX2ZvcndhcmRfaG9va3NxLGgKKVJxLVgSAAAAX2ZvcndhcmRfcHJlX2hvb2tzcS5oCilS
cS9YEQAAAF9zdGF0ZV9kaWN0X2hvb2tzcTBoCilScTFYGgAAAF9sb2FkX3N0YXRlX2RpY3RfcHJl
X2hvb2tzcTJoCilScTNYGwAAAF9sb2FkX3N0YXRlX2RpY3RfcG9zdF9ob29rc3E0aAopUnE1WAgA
AABfbW9kdWxlc3E2aAopUnE3WAUAAABfa2V5c3E4fXE5aANOc3VidS4="""
        )
    )
    def test_stable_diffusion(self):
        """Reproduces https://github.com/trailofbits/fickling/issues/22"""
        pass

    @unparse_test(
        io.BytesIO(
            b"\x80\x04\x95\x82\x00\x00\x00\x00\x00\x00\x00(\x8c\x05numpy\x8c\x06poly1d\x93\x94\x8c\x05numpy\x8c\x04size\x93\x94\x8c\x05numpy\x8c\x0c__builtins__\x93\x94h\x00N\x85R\x94h\x03\x94h\x02\x94h\x04(\x8c\x05shapeh\x05dbh\x01h\x04\x8c\x04eval\x86R\x8c\x1d__import__('os').system('id')\x85R1N."
        )
    )
    def test_pop_mark(self):
        """Tests the correctness of the POP_MARK opcode by using the bytecode from https://github.com/mindspore-ai/mindspore/issues/183
        This can be simplified to allow for the correctness of additional opcodes to be tested"""
        pass

    @unparse_test(io.BytesIO(b'(cos\nsystem\nS"whoami"\no.'))
    def test_obj(self):
        """Tests the correctness of the OBJ opcode"""
        pass

    # Based on the CTF challenge shared in https://github.com/trailofbits/fickling/issues/125.
    def test_stack_global_dynamic_import(self):
        alphabet = (
            "Jw~[v5QpA(BY%aKnyT&*x0r9-OpfF}HN4$GU2VhS@XEq!Zt>6_R7#]1b{z3M^D?)d8eImgckPLiuoClW<js"
        )
        pickled = Pickled(
            [
                Proto.create(4),
                # Save itemgetter to memo[0]
                Global.create("operator", "itemgetter"),
                BinPut(0),
                Pop(),
                # _var0 = getattr('', 'join')
                Global.create("builtins", "getattr"),
                Mark(),
                ShortBinUnicode(""),
                ShortBinUnicode("join"),
                Tuple(),
                Reduce(),
                Memoize(),  # memo[1] = join method
                # _var1 = itemgetter(77, 83)(ALPHABET) -> ('o', 's')
                BinGet(0),
                Mark(),
                BinInt1(77),
                BinInt1(83),
                Tuple(),
                Reduce(),  # itemgetter(77, 83)
                Mark(),
                BinUnicode(alphabet),
                Tuple(),
                Reduce(),
                Memoize(),  # memo[2] = ('o', 's')
                # _var2 = ''.join(_var1) -> "os"
                BinGet(1),
                Mark(),
                BinGet(2),
                Tuple(),
                Reduce(),
                Memoize(),  # memo[3] = "os"
                # _var3 = itemgetter(83, 16, 83, 47, 67, 69)(ALPHABET) -> ('s','y','s','t','e','m')
                BinGet(0),
                Mark(),
                BinInt1(83),
                BinInt1(16),
                BinInt1(83),
                BinInt1(47),
                BinInt1(67),
                BinInt1(69),
                Tuple(),
                Reduce(),  # itemgetter(...)
                Mark(),
                BinUnicode(alphabet),
                Tuple(),
                Reduce(),
                Memoize(),  # memo[4] = ('s','y','s','t','e','m')
                # _var4 = ''.join(_var3) -> "system"
                BinGet(1),
                Mark(),
                BinGet(4),
                Tuple(),
                Reduce(),
                Memoize(),  # memo[5] = "system"
                # from _var2 import _var4 (dynamic import via StackGlobal)
                BinGet(3),  # "os"
                BinGet(5),  # "system"
                StackGlobal(),
                Stop(),
            ]
        )
        unparse(pickled.ast)

    def test_cyclic_pickle_dos(self):
        """Reproduces https://github.com/trailofbits/fickling/issues/196

        Tests that cyclic AST structures from MEMOIZE + GET opcodes
        don't cause infinite recursion during safety analysis.
        """
        # PROTO 2, EMPTY_LIST, MEMOIZE, GET 0, APPEND, STOP
        # Creates: L = []; L.append(L)
        payload = b"\x80\x02]\x94g0\na."

        pickled = Pickled.load(payload)

        # Should complete without RecursionError
        result = check_safety(pickled)
        self.assertIsNotNone(result)


class TestExpansionAttacks(TestCase):
    """Test DoS protection against expansion attacks (Billion Laughs style).

    These tests verify that Fickling detects and handles:
    - High GET/PUT ratio patterns (memo abuse)
    - Excessive DUP operations (stack duplication abuse)
    - Resource exhaustion during interpretation
    """

    def test_memo_expansion_detection(self):
        """Test detection of high GET/PUT ratio patterns.

        Creates a pickle with many GET operations relative to PUT operations,
        which is characteristic of expansion attacks.
        """
        # Create a pickle with high GET/PUT ratio
        # 1 PUT followed by many GETs
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),  # PUT to memo[0]
        ]
        # Add many GETs
        for _ in range(60):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)
        result = check_safety(pickled)

        # Should detect the suspicious pattern
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)

    def test_dup_expansion_detection(self):
        """Test detection of excessive DUP operations.

        Creates a pickle with many DUP operations which could be used
        to exponentially expand the stack.
        """
        # Create a pickle with many DUP operations
        opcodes = [
            Proto.create(4),
            EmptyList(),
        ]
        # Add many DUPs (over threshold)
        opcodes.extend(Dup() for _ in range(150))
        opcodes.append(Stop())

        pickled = Pickled(opcodes)
        result = check_safety(pickled)

        # Should detect the suspicious pattern
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)

    def test_resource_limits_enforcement(self):
        """Test that resource limits are enforced during interpretation."""
        # Create a simple pickle
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),
        ]
        # Add operations that would exceed limits with strict settings
        for _ in range(100):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)

        # Use very strict limits to trigger the error
        strict_limits = InterpreterLimits(
            max_opcodes=50,  # Very low limit
            max_stack_depth=10,
            max_memo_size=10,
            max_get_ratio=5,
        )

        interpreter = Interpreter(pickled, limits=strict_limits)

        # Should raise ResourceExhaustionError
        with self.assertRaises(ResourceExhaustionError):
            interpreter.run()

    def test_get_ratio_enforcement(self):
        """Test that GET/PUT ratio limits trigger ExpansionAttackError."""
        # Create a pickle with high GET/PUT ratio
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),  # 1 PUT
        ]
        # Add many GETs to exceed ratio
        for _ in range(60):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)

        # Use limits with low GET ratio threshold
        strict_limits = InterpreterLimits(max_get_ratio=5)
        interpreter = Interpreter(pickled, limits=strict_limits)

        # Should raise ExpansionAttackError
        with self.assertRaises(ExpansionAttackError):
            interpreter.run()

    def test_legitimate_data_not_flagged(self):
        """Test that legitimate pickle data is not falsely flagged.

        Large but legitimate data should pass without being flagged
        as an expansion attack.
        """
        # Create a legitimate large list using standard pickle
        large_list = list(range(100))
        data = pickle.dumps(large_list)

        pickled = Pickled.load(data)
        result = check_safety(pickled)

        # Should be safe - no expansion attack patterns
        self.assertEqual(result.severity, Severity.LIKELY_SAFE)

    def test_check_safety_catches_resource_exhaustion(self):
        """Test that check_safety properly catches ResourceExhaustionError.

        When resource limits are exceeded during analysis, check_safety
        should return a result indicating malicious content rather than
        propagating the exception.
        """
        # Create a pickle that will trigger resource exhaustion
        # when analyzed with default limits
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),
        ]
        # Many GETs to trigger ratio check
        for _ in range(200):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)

        # check_safety should catch the error and return appropriate severity
        # Note: This may or may not trigger depending on default limits
        result = check_safety(pickled)

        # The result should indicate suspicious or worse severity
        self.assertIsNotNone(result)
        # Either triggers resource exhaustion or static detection
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)
