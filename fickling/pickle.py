import ast
import distutils.sysconfig as sysconfig
from abc import abstractmethod
from collections.abc import MutableSequence, Sequence
from pathlib import Path
from pickletools import genops, opcodes, OpcodeInfo
from typing import (
    Any, BinaryIO, ByteString, Dict, FrozenSet, Generic, Iterable,
    Iterator, List, Optional, overload, Set, Type, TypeVar, Union
)

import sys

T = TypeVar("T")

if sys.version_info < (3, 9):
    # abstract collections were not subscriptable until Python 3.9
    OpcodeSequence = MutableSequence
    GenericSequence = Sequence


    def make_constant(*args, **kwargs) -> ast.Constant:
        # prior to Python 3.9, the ast.Constant class did not have a `kind` member, but the `astunparse` module
        # expects that!
        ret = ast.Constant(*args, **kwargs)
        if not hasattr(ret, "kind"):
            setattr(ret, "kind", None)
        return ret

else:
    OpcodeSequence = MutableSequence["Opcode"]
    GenericSequence = Sequence[T]
    make_constant = ast.Constant

BUILTIN_MODULE_NAMES: FrozenSet[str] = frozenset(sys.builtin_module_names)
del sys

OPCODES_BY_NAME: Dict[str, Type["Opcode"]] = {}
OPCODE_INFO_BY_NAME: Dict[str, OpcodeInfo] = {
    opcode.name: opcode for opcode in opcodes
}

STD_LIB = sysconfig.get_python_lib(standard_lib=True)


def is_std_module(module_name: str) -> bool:
    base_path = Path(STD_LIB).joinpath(*module_name.split("."))
    return base_path.is_dir() or base_path.with_suffix(".py").is_file() or module_name in BUILTIN_MODULE_NAMES


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
                raise TypeError("The Opcode class must be constructed with the `info` argument")
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
            if info.name in OPCODES_BY_NAME:
                del kwargs["info"]
                return OPCODES_BY_NAME[info.name](*args, **kwargs)
            else:
                raise NotImplementedError(f"TODO: Add support for Opcode {info.name}")
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
        interpreter.stack.append(make_constant(self.arg))


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


class ASTProperties(ast.NodeVisitor):
    def __init__(self):
        self.imports: List[Union[ast.Import, ast.ImportFrom]] = []
        self.calls: List[ast.Call] = []
        self.non_setstate_calls: List[ast.Call] = []
        self.likely_safe_imports: Set[str] = set()

    def _process_import(self, node: Union[ast.Import, ast.ImportFrom]):
        self.imports.append(node)
        if isinstance(node, ast.ImportFrom) and is_std_module(node.module):
            self.likely_safe_imports |= {name.name for name in node.names}

    def visit_Import(self, node: ast.Import):
        self._process_import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self._process_import(node)

    def visit_Call(self, node: ast.Call):
        self.calls.append(node)
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "__setstate__":
            self.non_setstate_calls.append(node)


class Pickled(OpcodeSequence):
    def __init__(self, opcodes: Iterable[Opcode]):
        self._opcodes: List[Opcode] = list(opcodes)
        self._ast: Optional[ast.Module] = None
        self._properties: Optional[ASTProperties] = None

    def __len__(self) -> int:
        return len(self._opcodes)

    def __iter__(self) -> Iterator[Opcode]:
        return iter(self._opcodes)

    def __getitem__(self, index: int) -> Opcode:
        return self._opcodes[index]

    def insert(self, index: int, opcode: Opcode):
        self._opcodes.insert(index, opcode)
        self._ast = None
        self._properties = None

    def insert_python_exec(self, exec_cmd: str, run_first: bool = True, use_output_as_unpickle_result: bool = False):
        if not isinstance(self[-1], Stop):
            raise ValueError("Expected the last opcode to be STOP")
        """
        Similar to what Evan did down below, this imports the builtin exec function
        Exec works on statements, while eval works on expressions
        """
        self.insert(0, Global.create("__builtin__", "exec"))
        self.insert(1, Mark())
        # This might be a multiline exec, so lets just insert the payload one by one.
        self.insert(2, Unicode(exec_cmd.encode("utf-8")))
        self.insert(3, Tuple())
        if run_first:
            self.insert(4, Reduce())
            if use_output_as_unpickle_result:
                self.insert(-1, Pop())
        if not run_first:
            if use_output_as_unpickle_result:
                self.insert(-1, Pop())
                self.insert(-1, Reduce())
            else:
                interpreter = Interpreter(self)
                interpreter.run()
                memo_id = len(interpreter.memory)
                self.insert(-1, Memoize())
                self.insert(-1, Pop())
                self.insert(-1, Reduce())
                self.insert(-1, Get.create(memo_id))

        pass

    def insert_python_eval(self, eval_cmd: str, run_first: bool = True, use_output_as_unpickle_result: bool = False):
        if not isinstance(self[-1], Stop):
            raise ValueError("Expected the last opcode to be STOP")
        # we need to add the call to GLOBAL before the preexisting code, because the following code can sometimes
        # mess up module look (somehow? I, Evan, don't fully understand why yet).
        # So we set up the "import" of `__builtin__.eval` first, then set up the stack for a call to it,
        # and then either immediately call the `eval` with a `Reduce` opcode (the default)
        # or optionally insert the `Reduce` at the end (and hope that the existing code cleans up its stack so it
        # remains how we left it! TODO: Add code to emulate the code afterward and confirm that the stack is sane!
        self.insert(0, Global.create("__builtin__", "eval"))
        self.insert(1, Mark())
        self.insert(2, Unicode(eval_cmd.encode("utf-8")))
        self.insert(3, Tuple())
        if run_first:
            self.insert(4, Reduce())
            if use_output_as_unpickle_result:
                self.insert(-1, Pop())
        if not run_first:
            if use_output_as_unpickle_result:
                # the top of the stack should be the original unpickled value, but we can throw that away because
                # we are replacing it with the result of calling eval:
                self.insert(-1, Pop())
                # now the top of the stack should be our original Global, Mark, Unicode, Tuple setup, ready for Reduce:
                self.insert(-1, Reduce())
            else:
                # we need to preserve the "real" output of the preexisting unpickling, which should be at the top
                # of the stack, directly above our Tuple, Unicode, Mark, and Global stack items we added above.
                # So, we have to save the original result to the memo. First, interpret the existing code to see which
                # memo location it would be saved to:
                interpreter = Interpreter(self)
                interpreter.run()
                memo_id = len(interpreter.memory)
                self.insert(-1, Memoize())
                self.insert(-1, Pop())
                self.insert(-1, Reduce())
                self.insert(-1, Get.create(memo_id))

    def __setitem__(self, index: Union[int, slice], item: Union[Opcode, Iterable[Opcode]]):
        self._opcodes[index] = item
        self._ast = None
        self._properties = None

    def __delitem__(self, index: int):
        del self._opcodes[index]
        self._ast = None
        self._properties = None

    def dumps(self) -> bytes:
        b = bytearray()
        for opcode in self:
            b.extend(opcode.data)
        return bytes(b)

    def dump(self, file: BinaryIO):
        for opcode in self:
            file.write(opcode.data)

    @property
    def opcodes(self) -> Iterator[Opcode]:
        return iter(self)

    @staticmethod
    def load(pickled: Union[ByteString, BinaryIO]) -> "Pickled":
        if not isinstance(pickled, (bytes, bytearray)) and hasattr(pickled, "read"):
            pickled = pickled.read()
        opcodes: List[Opcode] = []
        for info, arg, pos in genops(pickled):
            if info.arg is None or info.arg.n == 0:
                if pos is not None:
                    data = pickled[pos:pos + 1]
                else:
                    data = info.code
            elif info.arg.n > 0 and pos is not None:
                data = pickled[pos:pos + 1 + info.arg.n]
            else:
                data = None
            if pos is not None and opcodes and opcodes[-1].pos is not None and not opcodes[-1].has_data():
                opcodes[-1].data = pickled[opcodes[-1].pos:pos]
            opcodes.append(Opcode(info=info, argument=arg, data=data, position=pos))
        if opcodes and not opcodes[-1].has_data() and opcodes[-1].pos is not None:
            opcodes[-1].data = pickled[opcodes[-1].pos:]
        return Pickled(opcodes)

    @property
    def properties(self) -> ASTProperties:
        if self._properties is None:
            self._properties = ASTProperties()
            self._properties.visit(self.ast)
        return self._properties

    @property
    def has_import(self) -> bool:
        """Checks whether unpickling would cause an import to be run"""
        return bool(self.properties.imports)

    @property
    def has_call(self) -> bool:
        """Checks whether unpickling would cause a function call"""
        return bool(self.properties.calls)

    @property
    def has_non_setstate_call(self) -> bool:
        """Checks whether unpickling would cause a call to a function other than object.__setstate__"""
        return bool(self.properties.non_setstate_calls)

    @property
    def is_likely_safe(self) -> bool:
        # `self.has_call` is probably safe as long as `not self.has_import`
        return not self.has_import and not self.has_non_setstate_call

    def unsafe_imports(self) -> Iterator[Union[ast.Import, ast.ImportFrom]]:
        for node in self.properties.imports:
            if node.module in ("__builtin__", "os", "subprocess", "sys", "builtins"):
                yield node
            elif "eval" in (n.name for n in node.names):
                yield node

    def non_standard_imports(self) -> Iterator[Union[ast.Import, ast.ImportFrom]]:
        for node in self.properties.imports:
            if not is_std_module(node.module):
                yield node

    @property
    def ast(self) -> ast.Module:
        if self._ast is None:
            self._ast = Interpreter.interpret(self)
        return self._ast


class Stack(GenericSequence, Generic[T]):
    def __init__(self, initial_value: Iterable[T] = ()):
        self._stack: List[T] = list(initial_value)
        self.opcode: Optional[Opcode] = None

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> T:
        ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> GenericSequence:
        ...

    def __getitem__(self, i: int) -> T:
        return self._stack[i]

    def __len__(self) -> int:
        return len(self._stack)

    def pop(self):
        if not self._stack:
            if self.opcode is None:
                raise IndexError("Stack is empty")
            else:
                raise IndexError(f"Opcode {self.opcode!s} attempted to pop from an empty stack")
        else:
            return self._stack.pop()

    def push(self, obj: T):
        self._stack.append(obj)

    append = push

    def __str__(self):
        return str(self._stack)

    def __repr__(self):
        return f"{self.__class__.__name__}(initial_value={self._stack!r})"


class ModuleBody:
    def __init__(self, interpreter: "Interpreter"):
        self._list: List[ast.stmt] = []
        self.interpreter: Interpreter = interpreter

    def append(self, stmt: ast.stmt):
        lineno = len(self._list) + 1
        if hasattr(stmt, "lineno") and stmt.lineno is not None and stmt.lineno != lineno:
            raise ValueError(
                f"Statement {stmt} was expected to have line number {lineno} but instead has {stmt.lineno}"
            )
        setattr(stmt, "lineno", lineno)
        self._list.append(stmt)

    def extend(self, stmts: Iterable[ast.stmt]):
        for stmt in stmts:
            self.append(stmt)

    def __iter__(self) -> Iterator[ast.stmt]:
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __getitem__(self, index: Union[int, slice]) -> ast.stmt:
        return self._list[index]


class Interpreter:
    def __init__(self, pickled: Pickled):
        self.pickled: Pickled = pickled
        self.memory: Dict[int, ast.expr] = {}
        self.stack: Stack[Union[ast.expr, MarkObject]] = Stack()
        self.module_body: ModuleBody = ModuleBody(self)
        self._module: Optional[ast.Module] = None
        self._var_counter: int = 0
        self._opcodes: Iterator[Opcode] = iter(pickled)

    def to_ast(self) -> ast.Module:
        if self._module is None:
            self.run()
        return self._module

    def stop(self):
        self._opcodes = iter(())

    def run(self):
        while True:
            try:
                self.step()
            except StopIteration:
                break

    def step(self) -> Opcode:
        try:
            opcode = next(self._opcodes)
            finished = False
        except StopIteration:
            # we finished running the program
            finished = True
        if finished:
            for i, stmt in enumerate(self.module_body):
                setattr(stmt, "lineno", i + 1)
                setattr(stmt, "col_offset", 0)
            self._module = ast.Module(list(self.module_body), type_ignores=[])
            raise StopIteration()
        self.stack.opcode = opcode
        opcode.run(self)
        return opcode

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
        if module == "__builtin__":
            # no need to emit an import for builtins!
            pass
        else:
            interpreter.module_body.append(ast.ImportFrom(module=module, names=[ast.alias(attr)], level=0))
        interpreter.stack.append(ast.Name(attr, ast.Load()))

    def encode(self) -> bytes:
        return f"c{self.module}\n{self.attr}\n".encode("utf-8")


class StackGlobal(NoOp):
    name = "STACK_GLOBAL"

    def run(self, interpreter: Interpreter):
        attr = interpreter.stack.pop()
        module = interpreter.stack.pop()
        if isinstance(module, ast.Constant):
            module = module.value
        if isinstance(attr, ast.Constant):
            attr = attr.value
        if module == "__builtin__":
            # no need to emit an import for builtins!
            pass
        else:
            interpreter.module_body.append(ast.ImportFrom(module=module, names=[ast.alias(attr)], level=0))
        interpreter.stack.append(ast.Name(attr, ast.Load()))


class Put(Opcode):
    name = "PUT"

    def run(self, interpreter: Interpreter):
        interpreter.memory[self.arg] = interpreter.stack[-1]


class BinPut(Opcode):
    name = "BINPUT"

    def run(self, interpreter: Interpreter):
        interpreter.memory[self.arg] = interpreter.stack[-1]


class LongBinPut(BinPut):
    name = "LONG_BINPUT"


class EmptyTuple(Opcode):
    name = "EMPTY_TUPLE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Tuple((), ast.Load()))


class TupleOne(Opcode):
    name = "TUPLE1"

    def run(self, interpreter: Interpreter):
        stack_top = interpreter.stack.pop()
        interpreter.stack.push(ast.Tuple((stack_top,), ast.Load()))


class TupleTwo(Opcode):
    name = "TUPLE2"

    def run(self, interpreter: Interpreter):
        arg2 = interpreter.stack.pop()
        arg1 = interpreter.stack.pop()
        interpreter.stack.append(ast.Tuple((arg1, arg2), ast.Load()))


class TupleThree(Opcode):
    name = "TUPLE3"

    def run(self, interpreter: Interpreter):
        top = interpreter.stack.pop()
        mid = interpreter.stack.pop()
        bot = interpreter.stack.pop()
        interpreter.stack.append(ast.Tuple((bot, mid, top), ast.Load()))


class Reduce(Opcode):
    name = "REDUCE"

    def run(self, interpreter: Interpreter):
        args = interpreter.stack.pop()
        func = interpreter.stack.pop()
        if isinstance(args, ast.Tuple):
            call = ast.Call(func, list(args.elts), [])
        else:
            call = ast.Call(func, [ast.Starred(args)], [])
        # Any call to reduce can have global side effects, since it runs arbitrary Python code.
        # However, if we just save it to the stack, then it might not make it to the final AST unless the stack
        # value is actually used. So save the result to a temp variable, and then put that on the stack:
        var_name = interpreter.new_variable(call)
        interpreter.stack.append(ast.Name(var_name, ast.Load()))


class Mark(Opcode):
    name = "MARK"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(MarkObject())


class Pop(Opcode):
    name = "POP"

    def run(self, interpreter: Interpreter):
        interpreter.stack.pop()


class Unicode(ConstantOpcode):
    name = "UNICODE"

    def encode(self) -> bytes:
        return self.info.code.encode("latin-1") + raw_unicode_escape(self.arg).encode("utf-8")


class BinUnicode(ConstantOpcode):
    name = "BINUNICODE"


class ShortBinUnicode(BinUnicode):
    name = "SHORT_BINUNICODE"

    def encode(self) -> bytes:
        text = self.arg
        if isinstance(text, str):
            text = text.encode("utf-8")
        if len(text) > 0xFF:
            raise ValueError(f"{self.arg!r} is too long for a {self.name}")
        return self.info.code.encode("latin-1") + bytes([len(text)]) + text


class String(ConstantOpcode):
    name = "STRING"


class NewObj(Opcode):
    name = "NEWOBJ"

    def run(self, interpreter: Interpreter):
        args = interpreter.stack.pop()
        class_type = interpreter.stack.pop()
        if isinstance(args, ast.Tuple):
            interpreter.stack.append(ast.Call(class_type, list(args.elts), []))
        else:
            interpreter.stack.append(ast.Call(class_type, [ast.Starred(args)], []))


class NewObjEx(Opcode):
    name = "NEWOBJ_EX"

    def run(self, interpreter: Interpreter):
        kwargs = interpreter.stack.pop()
        args = interpreter.stack.pop()
        class_type = interpreter.stack.pop()
        if isinstance(args, ast.Tuple):
            interpreter.stack.append(ast.Call(class_type, list(args.elts), kwargs))
        else:
            interpreter.stack.append(ast.Call(class_type, [ast.Starred(args)], kwargs))


class BinPersId(Opcode):
    name = "BINPERSID"

    def run(self, interpreter: Interpreter):
        pid = interpreter.stack.pop()
        interpreter.stack.append(
            ast.Call(ast.Attribute(ast.Name("UNPICKLER", ast.Load()), "persistent_load"), [pid], [])
        )


class NoneOpcode(Opcode):
    name = "NONE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(make_constant(None))


class NewTrue(Opcode):
    name = "NEWTRUE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(make_constant(True))


class NewFalse(Opcode):
    name = "NEWFALSE"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(make_constant(False))


class Tuple(StackSliceOpcode):
    name = "TUPLE"

    def run(self, interpreter: Interpreter, stack_slice: List[ast.expr]):
        interpreter.stack.append(ast.Tuple(tuple(stack_slice), ast.Load()))


class Build(Opcode):
    name = "BUILD"

    def run(self, interpreter: Interpreter):
        argument = interpreter.stack.pop()
        obj = interpreter.stack.pop()
        obj_name = interpreter.new_variable(obj)
        interpreter.module_body.append(ast.Expr(
            ast.Call(ast.Attribute(ast.Name(obj_name, ast.Load()), "__setstate__"), [argument], [])
        ))
        interpreter.stack.append(ast.Name(obj_name, ast.Load()))


class BinGet(Opcode):
    name = "BINGET"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(interpreter.memory[self.arg])


class LongBinGet(Opcode):
    name = "LONG_BINGET"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(interpreter.memory[self.arg])


class Get(Opcode):
    name = "GET"

    @property
    def memo_id(self) -> int:
        return int(self.arg)

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(interpreter.memory[self.memo_id])

    def encode(self) -> bytes:
        return self.info.code.encode("latin-1") + f"{self.memo_id}\n".encode("utf-8")

    @staticmethod
    def create(memo_id: int) -> "Get":
        return Get(f"{memo_id}\n".encode("utf-8"))


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
                ast.Call(ast.Attribute(ast.Name(dict_name, ast.Load()), "update"), [update_dict], [])
            ))
            interpreter.stack.append(ast.Name(dict_name, ast.Load()))


class SetItem(Opcode):
    name = "SETITEM"

    def run(self, interpreter: Interpreter):
        value = interpreter.stack.pop()
        key = interpreter.stack.pop()
        pydict = interpreter.stack.pop()
        if isinstance(pydict, ast.Dict) and not pydict.keys:
            # the dict is empty, so add a new one
            interpreter.stack.append(ast.Dict(keys=[key], values=[value]))
        else:
            dict_name = interpreter.new_variable(pydict)
            assignment = ast.Assign([ast.Subscript(ast.Name(dict_name, ast.Load()), key, ast.Store())], value)
            interpreter.module_body.append(assignment)
            interpreter.stack.append(ast.Name(dict_name, ast.Load()))


class Stop(Opcode):
    name = "STOP"

    def run(self, interpreter: Interpreter):
        interpreter.new_variable(interpreter.stack.pop(), name="result")
        interpreter.stop()


class Frame(NoOp):
    name = "FRAME"


class BinInt1(ConstantOpcode):
    name = "BININT1"


class BinInt2(BinInt1):
    name = "BININT2"


class EmptySet(Opcode):
    name = "EMPTY_SET"

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(ast.Set([]))


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


class BinFloat(ConstantOpcode):
    name = "BINFLOAT"


class BinBytes(ConstantOpcode):
    name = "BINBYTES"


class ShortBinBytes(BinBytes):
    name = "SHORT_BINBYTES"


class Int(ConstantOpcode):
    name = "INT"


class Dict(Opcode):
    name = "DICT"

    def run(self, interpreter: Interpreter):
        i = 0
        keys = []
        values = []

        while interpreter.stack:
            obj = interpreter.stack.pop()
            if isinstance(obj, MarkObject):
                break
            if i == 0:
                values.append(obj)
            elif i == 1:
                keys.append(obj)
            i = (i + 1) % 2
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")

        if len(keys) != len(values):
            raise ValueError(f"Number of keys ({len(keys)}) and values ({len(values)}) for DICT do not match")            

        interpreter.stack.append(ast.Dict(keys=keys, values=values))
