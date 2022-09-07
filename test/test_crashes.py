"""
This test module checks against inputs that previously caused crashes
"""

from base64 import b64decode
from functools import wraps
from pickle import dumps, loads
from sys import version_info
from unittest import TestCase

if version_info >= (3, 9):
    from ast import unparse as unparse9

from astunparse import unparse

from fickling import pickle as fpickle
from fickling.pickle import Pickled


def unparse_test(pickled: bytes):
    def decorator(func):
        @wraps(func)
        def wrapper(self: TestCase):
            ast = Pickled.load(pickled).ast
            if version_info >= (3, 9):
                _ = unparse9(ast)
            _ = unparse(ast)
        return wrapper
    return decorator


class TestCrashes(TestCase):
    @unparse_test(b64decode("""gAJ9cQAoWA8AAABzdHJpbmdfdG9fdG9rZW5xAX1xAlgBAAAAKnEDY3RvcmNoLl91dGlscwpfcmVi
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
AABfbW9kdWxlc3E2aAopUnE3WAUAAABfa2V5c3E4fXE5aANOc3VidS4="""))
    def test_stable_diffusion(self):
        """Reproduces https://github.com/trailofbits/fickling/issues/22"""
        pass
