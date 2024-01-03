import io

from astunparse import unparse

import fickling.tracing as tracing
from fickling.fickle import Interpreter, Pickled

# Grab mystery binary object
# This comes from https://github.com/maurosoria/dirsearch/issues/1073
mystery = b"\x80\x04\x95E\x00\x00\x00\x00\x00\x00\x00(\x8c\x08builtins\x8c\x07getattr\x93\x8c\x08builtins\x8c\n__import__\x93\x8c\x02os\x85R\x8c\x06system\x86R\x8c\x02id\x85R1N."  # noqa
binary = io.BytesIO(mystery)

# Load using fickling
fickled = Pickled.load(binary)

# Trace and print decompiled output
interpreter = Interpreter(fickled)
trace = tracing.Trace(interpreter)
print(unparse(trace.run()))

"""
Expected Output:

PROTO
FRAME
MARK
        Pushed MARK
SHORT_BINUNICODE
        Pushed 'builtins'
SHORT_BINUNICODE
        Pushed 'getattr'
STACK_GLOBAL
        Popped 'getattr'
        Popped 'builtins'
        Pushed getattr
SHORT_BINUNICODE
        Pushed 'builtins'
SHORT_BINUNICODE
        Pushed '__import__'
STACK_GLOBAL
        Popped '__import__'
        Popped 'builtins'
        Pushed __import__
SHORT_BINUNICODE
        Pushed 'os'
TUPLE1
        Popped 'os'
        Pushed ('os',)
REDUCE
        _var0 = __import__('os')
        Popped ('os',)
        Popped __import__
        Pushed _var0
SHORT_BINUNICODE
        Pushed 'system'
TUPLE2
        Popped 'system'
        Popped _var0
        Pushed (_var0, 'system')
REDUCE
        _var1 = getattr(_var0, 'system')
        Popped (_var0, 'system')
        Popped getattr
        Pushed _var1
SHORT_BINUNICODE
        Pushed 'id'
TUPLE1
        Popped 'id'
        Pushed ('id',)
REDUCE
        _var2 = _var1('id')
        Popped ('id',)
        Popped _var1
        Pushed _var2
POP_MARK
        Popped _var2
        Popped MARK
NONE
        Pushed None
STOP
        result = None
        Popped None

_var0 = __import__('os')
_var1 = getattr(_var0, 'system')
_var2 = _var1('id')
result = None
"""
