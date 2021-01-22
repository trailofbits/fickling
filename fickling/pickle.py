import ast
from collections.abc import MutableSequence
from io import BytesIO
from pickletools import genops, opcodes, OpcodeInfo
from typing import Any, ByteString, Dict, Iterable, Iterator, List, Optional, Type, Union

OPCODES_BY_NAME: Dict[str, Type["Opcode"]] = {}
OPCODE_INFO_BY_NAME: Dict[str, OpcodeInfo] = {
    opcode.name: opcode for opcode in opcodes
}


class MarkObject:
    pass


class Opcode:
    name: str
    info: OpcodeInfo

    def __init__(
            self,
            argument: Optional[Any] = None,
            position: Optional[int] = None,
            data: Optional[bytes] = None,
            *,
            info: Optional[OpcodeInfo] = None
    ):
        if self.__class__ is Opcode:
            if info is None:
                raise TypeError(f"The Opcode class must be constructed with the `info` argument")
        elif info is not None and info != self.info:
            raise ValueError(f"Invalid info type for {self.__class__.__name__}; expected {self.info!r} but got "
                             f"{info!r}")
        self.arg: Any = argument
        self.pos: Optional[int] = position
        self._data: Optional[bytes] = data

    def has_data(self) -> bool:
        return self._data is not None

    @property
    def data(self) -> bytes:
        if self._data is None:
            return self.encode()
        else:
            return self._data

    @data.setter
    def data(self, value: bytes):
        self._data = value

    def encode(self) -> bytes:
        if self.info.arg is None or self.info.arg.n == 0:
            return self.info.code.encode("latin-1")
        raise NotImplementedError(f"encode() is not yet implemented for opcode {self.__class__.__name__}")

    def __new__(cls, *args, **kwargs):
        if cls is Opcode:
            if "info" not in kwargs:
                raise ValueError(f"You must provide an `info` argument to construct {cls.__name__}")
            else:
                info = kwargs["info"]
                del kwargs["info"]
            if info.name in OPCODES_BY_NAME:
                return OPCODES_BY_NAME[info.name](*args, **kwargs)
        return super().__new__(cls)

    def run(self, interpreter: "Interpreter"):
        raise NotImplementedError(f"TODO: Add support for Pickle opcode {self.info.name}")

    def __init_subclass__(cls, **kwargs):
        if cls.__name__ not in ("NoOp", "StackSliceOpcode", "ConstantOpcode"):
            if not hasattr(cls, "name") or cls.name is None:
                raise TypeError("Opcode subclasses must define a name")
            elif cls.name in OPCODES_BY_NAME:
                raise TypeError(f"An Opcode named {cls.name} is already defined")
            elif cls.name not in OPCODE_INFO_BY_NAME:
                raise TypeError(f"An Opcode named {cls.name} is not defined in `pickletools`")
            OPCODES_BY_NAME[cls.name] = cls
            setattr(cls, "info", OPCODE_INFO_BY_NAME[cls.name])
            # find the associated `pickletools` OpcodeInfo:
        return super().__init_subclass__(**kwargs)

    def __repr__(self):
        if self.pos is None:
            p = ""
        else:
            p = f", position={self.pos!r}"
        if self.has_data():
            d = f", data={self.data!r}"
        else:
            d = ""
        return f"{self.__class__.__name__}(info={self.info!r}, argument={self.arg!r}{d}{p})"


class NoOp(Opcode):
    def run(self, interpreter: "Interpreter"):
        pass


def raw_unicode_escape(byte_string: bytes) -> str:
    s = []
    for b in byte_string:
        if 32 <= b <= 128:
            # this is printable ASCII
            s.append(chr(b))
        elif b == ord("\n"):
            s.append("\\n")
        elif b == ord("\r"):
            s.append("\\r")
        elif b == ord("\\"):
            s.append("\\\\")
        else:
            s.append(f"\\u{b:04x}")
    s.append("\n")
    return "".join(s)


class ConstantOpcode(Opcode):
    def run(self, interpreter: "Interpreter"):
        interpreter.stack.append(ast.Constant(self.arg))


class StackSliceOpcode(Opcode):
    def run(self, interpreter: "Interpreter", stack_slice: List[ast.expr]):
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    def __init_subclass__(cls, **kwargs):
        ret = super().__init_subclass__(**kwargs)
        orig_run = cls.run

        def run_wrapper(self, interpreter: "Interpreter"):
            args = []
            while True:
                if not interpreter.stack:
                    raise ValueError("Exhausted the stack while searching for a MarkObject!")
                obj = interpreter.stack.pop()
                if isinstance(obj, MarkObject):
                    break
                else:
                    args.append(obj)
            args = list(reversed(args))
            return orig_run(self, interpreter, args)

        setattr(cls, "run", run_wrapper)

        return ret


class Pickled(MutableSequence[Opcode]):
    def __init__(self, opcodes: Iterable[Opcode]):
        self._opcodes: List[Opcode] = list(opcodes)
        self._ast: Optional[ast.Module] = None

    def __len__(self) -> int:
        return len(self._opcodes)

    def __iter__(self) -> Iterator[Opcode]:
        return iter(self._opcodes)

    def __getitem__(self, index: int) -> Opcode:
        return self._opcodes[index]

    def insert(self, index: int, opcode: Opcode):
        self._opcodes.insert(index, opcode)
        self._ast = None

    def __setitem__(self, index: Union[int, slice], item: Union[Opcode, Iterable[Opcode]]):
        self._opcodes[index] = item
        self._ast = None

    def __delitem__(self, index: int):
        del self._opcodes[index]
        self._ast = None

    def dumps(self) -> bytes:
        b = bytearray()
        for opcode in self:
            b.extend(opcode.data)
        return bytes(b)

    def dump(self, file: BytesIO):
        for opcode in self:
            file.write(opcode.data)

    @property
    def opcodes(self) -> Iterator[Opcode]:
        return iter(self)

    @staticmethod
    def load(pickled: Union[ByteString, BytesIO]) -> "Pickled":
        if not isinstance(pickled, (bytes, bytearray)) and hasattr(pickled, "read"):
            pickled = pickled.read()
        opcodes: List[Opcode] = []
        for info, arg, pos in genops(pickled):
            if info.arg is None or info.arg.n == 0:
                if pos is not None:
                    data = pickled[pos:pos+1]
                else:
                    data = info.code
            elif info.arg.n > 0 and pos is not None:
                data = pickled[pos:pos+1+info.arg.n]
            else:
                data = None
            if pos is not None and opcodes and opcodes[-1].pos is not None and not opcodes[-1].has_data():
                opcodes[-1].data = pickled[opcodes[-1].pos:pos]
            opcodes.append(Opcode(info=info, argument=arg, data=data, position=pos))
        if opcodes and not opcodes[-1].has_data() and opcodes[-1].pos is not None:
            opcodes[-1].data = pickled[opcodes[-1].pos:]
        return Pickled(opcodes)

    @property
    def ast(self) -> ast.Module:
        if self._ast is None:
            self._ast = Interpreter.interpret(self)
        return self._ast


class Interpreter:
    def __init__(self, pickled: Pickled):
        self.pickled: Pickled = pickled
        self.memory: Dict[int, ast.expr] = {}
        self.stack: List[Union[ast.expr, MarkObject]] = []
        self.module_body: List[ast.stmt] = []
        self._module: Optional[ast.Module] = None
        self._var_counter: int = 0

    def to_ast(self) -> ast.Module:
        if self._module is None:
            for opcode in self.pickled:
                opcode.run(self)
            for i, stmt in enumerate(self.module_body):
                setattr(stmt, "lineno", i + 1)
                setattr(stmt, "col_offset", 0)
            self._module = ast.Module(list(self.module_body))
        return self._module

    def new_variable(self, value: ast.expr, name: Optional[str] = None) -> str:
        if name is None:
            name = f"_var{self._var_counter}"
            self._var_counter += 1
        self.module_body.append(ast.Assign([ast.Name(name, ast.Store())], value))
        return name

    @staticmethod
    def interpret(pickled: Pickled) -> ast.Module:
        return Interpreter(pickled).to_ast()

    def __str__(self):
        return ast.dump(self.to_ast())


class Proto(NoOp):
    name = "PROTO"


class Global(Opcode):
    name = "GLOBAL"

    @staticmethod
    def create(module: str, attr: str) -> "Global":
        return Global(f"{module} {attr}")

    @property
    def module(self) -> str:
        return next(iter(self.arg.split(" ")))

    @property
    def attr(self) -> str:
        _, attribute, *_ = self.arg.split(" ")
        return attribute

    def run(self, interpreter: Interpreter):
        module, attr = self.module, self.attr
        interpreter.module_body.append(ast.ImportFrom(module=module, names=[ast.alias(attr)], level=0))
        interpreter.stack.append(ast.Name(attr, ast.Load()))

    def encode(self) -> bytes:
        return f"c{self.module}\n{self.attr}\n".encode("utf-8")


class BinPut(Opcode):
    name = "BINPUT"

    def run(self, interpreter: Interpreter):
        interpreter.memory[self.arg] = interpreter.stack[-1]


class LongBinPut(BinPut):
    name = "LONG_BINPUT"


class EmptyTuple(Opcode):
    name = "EMPTY_TUPLE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Tuple(()))


class Reduce(Opcode):
    name = "REDUCE"

    def run(self, interpreter: Interpreter):
        args = interpreter.stack.pop()
        func = interpreter.stack.pop()
        if isinstance(args, ast.Tuple):
            interpreter.stack.append(ast.Call(func, args=list(args.elts), keywords=[]))
        else:
            interpreter.stack.append(ast.Call(func, args=[ast.Starred(args)], keywords=[]))


class Mark(Opcode):
    name = "MARK"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(MarkObject())


class Unicode(ConstantOpcode):
    name = "UNICODE"

    def encode(self) -> bytes:
        return self.info.code.encode("latin-1") + raw_unicode_escape(self.arg).encode("utf-8")


class BinUnicode(ConstantOpcode):
    name = "BINUNICODE"


class ShortBinUnicode(BinUnicode):
    name = "SHORT_BINUNICODE"


class NewObj(Opcode):
    name = "NEWOBJ"

    def run(self, interpreter: Interpreter):
        args = interpreter.stack.pop()
        class_type = interpreter.stack.pop()
        if isinstance(args, ast.Tuple):
            interpreter.stack.append(ast.Call(class_type, args=list(args.elts), keywords=[]))
        else:
            interpreter.stack.append(ast.Call(class_type, args=[ast.Starred(args)], keywords=[]))


class BinPersId(Opcode):
    name = "BINPERSID"

    def run(self, interpreter: Interpreter):
        pid = interpreter.stack.pop()
        interpreter.stack.append(
            ast.Call(ast.Attribute(ast.Name("UNPICKLER", ast.Load()), "persistent_load"), args=[pid], keywords=[])
        )


class NoneOpcode(Opcode):
    name = "NONE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Constant(None))


class NewTrue(Opcode):
    name = "NEWTRUE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Constant(True))


class NewFalse(Opcode):
    name = "NEWFALSE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Constant(False))


class Tuple(StackSliceOpcode):
    name = "TUPLE"

    def run(self, interpreter: Interpreter, stack_slice: List[ast.expr]):
        interpreter.stack.append(ast.Tuple(tuple(stack_slice)))


class Build(Opcode):
    name = "BUILD"

    def run(self, interpreter: Interpreter):
        argument = interpreter.stack.pop()
        obj = interpreter.stack.pop()
        obj_name = interpreter.new_variable(obj)
        interpreter.module_body.append(ast.Expr(
            ast.Call(ast.Attribute(ast.Name(obj_name, ast.Load()), "__setstate__"), args=[argument], keywords=[])
        ))
        interpreter.stack.append(ast.Name(obj_name, ast.Load()))


class BinGet(Opcode):
    name = "BINGET"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(interpreter.memory[self.arg])


class SetItems(StackSliceOpcode):
    name = "SETITEMS"

    def run(self, interpreter: Interpreter, stack_slice: List[ast.expr]):
        pydict = interpreter.stack.pop()
        update_dict_keys = []
        update_dict_values = []
        for key, value in zip(stack_slice[::2], stack_slice[1::2]):
            update_dict_keys.append(key)
            update_dict_values.append(value)
        if isinstance(pydict, ast.Dict) and not pydict.keys:
            # the dict is empty, so add a new one
            interpreter.stack.append(ast.Dict(keys=update_dict_keys, values=update_dict_values))
        else:
            dict_name = interpreter.new_variable(pydict)
            update_dict = ast.Dict(keys=update_dict_keys, values=update_dict_values)
            interpreter.module_body.append(ast.Expr(
                ast.Call(ast.Attribute(ast.Name(dict_name, ast.Load()), "update"), args=[update_dict], keywords=[])
            ))
            interpreter.stack.append(ast.Name(dict_name, ast.Load()))


class Stop(Opcode):
    name = "STOP"

    def run(self, interpreter: Interpreter):
        interpreter.new_variable(interpreter.stack.pop(), name="result")


class Frame(NoOp):
    name = "FRAME"


class BinInt1(ConstantOpcode):
    name = "BININT1"


class BinInt2(BinInt1):
    name = "BININT2"


class EmptyList(Opcode):
    name = "EMPTY_LIST"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.List([], ast.Load()))


class EmptyDict(Opcode):
    name = "EMPTY_DICT"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Dict(keys=[], values=[]))


class Memoize(Opcode):
    name = "MEMOIZE"

    def run(self, interpreter: Interpreter):
        interpreter.memory[len(interpreter.memory)] = interpreter.stack[-1]


class Appends(StackSliceOpcode):
    name = "APPENDS"

    def run(self, interpreter: Interpreter, stack_slice: List[ast.expr]):
        list_obj = interpreter.stack[-1]
        if isinstance(list_obj, ast.List):
            list_obj.elts.extend(stack_slice)
        else:
            raise ValueError(f"Expected a list on the stack, but instead found {list_obj!r}")


class BinBytes(ConstantOpcode):
    name = "BINBYTES"


class ShortBinBytes(BinBytes):
    name = "SHORT_BINBYTES"
