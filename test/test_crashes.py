"""
This test module checks against inputs that previously caused crashes
"""

import io
from ast import unparse
from base64 import b64decode
from functools import wraps
from unittest import TestCase

from fickling.fickle import (
    BinGet,
    BinInt1,
    BinPut,
    BinUnicode,
    Global,
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

    def test_missing_mark_before_tuple(self):
        """Reproduces https://github.com/trailofbits/fickling/issues/188"""
        from fickling.analysis import Severity, check_safety

        # PROTO 4, TUPLE (0x74='t', requires preceding MARK), STOP
        malformed_bytes = b"\x80\x04t."
        loaded = Pickled.load(io.BytesIO(malformed_bytes))

        # Should not crash when accessing AST
        _ = loaded.ast

        # Should flag as having interpretation error
        self.assertTrue(loaded.has_interpretation_error)

        # Safety check should flag it
        results = check_safety(loaded)
        self.assertGreater(results.severity, Severity.LIKELY_SAFE)
