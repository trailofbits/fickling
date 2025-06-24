from __future__ import annotations

import ast
import marshal
import re
import struct
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, MutableSequence, Sequence
from enum import Enum
from io import BytesIO
from pickletools import OpcodeInfo, genops, opcodes
from typing import (
    Any,
    BinaryIO,
    Generic,
    TypeVar,
    overload,
)

from stdlib_list import in_stdlib

from fickling.exception import WrongMethodError

T = TypeVar("T")

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer


OpcodeSequence = MutableSequence["Opcode"]
GenericSequence = Sequence[T]
make_constant = ast.Constant

BUILTIN_MODULE_NAMES: frozenset[str] = frozenset(sys.builtin_module_names)

OPCODES_BY_NAME: dict[str, type[Opcode]] = {}
OPCODE_INFO_BY_NAME: dict[str, OpcodeInfo] = {opcode.name: opcode for opcode in opcodes}


def is_std_module(module_name: str) -> bool:
    return in_stdlib(module_name) or module_name in BUILTIN_MODULE_NAMES


class MarkObject:
    pass


class Opcode:
    name: str
    info: OpcodeInfo

    def __init__(
        self,
        argument: Any | None = None,
        position: int | None = None,
        data: bytes | None = None,
        *,
        info: OpcodeInfo | None = None,
    ):
        if self.__class__ is Opcode:
            if info is None:
                raise TypeError("The Opcode class must be constructed with the `info` argument")
        elif info is not None and info != self.info:
            raise ValueError(f"Invalid info type for {self.__class__.__name__}; expected {self.info!r} but got " f"{info!r}")
        self.arg: Any = argument
        self.pos: int | None = position
        self._data: bytes | None = data

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
        return self.encode_opcode() + self.encode_body()

    def encode_opcode(self) -> bytes:
        return self.info.code.encode("latin-1")

    def encode_body(self) -> bytes:
        if self.info.arg is None or self.info.arg.n == 0:
            return b""
        raise NotImplementedError(f"encode_body() is not yet implemented for opcode {self.__class__.__name__}")

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

    def run(self, interpreter: Interpreter):
        raise NotImplementedError(f"TODO: Add support for Pickle opcode {self.info.name}")

    def __init_subclass__(cls, **kwargs):
        if cls.__name__ not in (
            "NoOp",
            "StackSliceOpcode",
            "ConstantOpcode",
            "DynamicLength",
            "ConstantInt",
        ):
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


class Endianness(Enum):
    Little = "<"
    Big = ">"


class DynamicLength(Opcode, ABC):
    length_signed: bool = False
    length_bytes: int = 4
    length_endianness: Endianness = Endianness.Little
    struct_types = {1: "b", 2: "h", 4: "i", 8: "q"}
    min_value: int
    max_value: int

    def __init_subclass__(cls, **kwargs):
        ret = super().__init_subclass__(**kwargs)
        length_bits = cls.length_bytes * 8
        if cls.length_signed:
            cls.min_value = 1 << (length_bits - 1)
            cls.max_value = cls.min_value ^ (2**length_bits - 1)
        else:
            cls.min_value = 0
            cls.max_value = 2**length_bits - 1
        return ret

    @classmethod
    def encode_length(cls, length: int) -> bytes:
        if cls.length_bytes not in cls.struct_types:
            raise TypeError(
                f"{cls.__name__}.struct_types does not include a value for " f"{cls.__name__}.length_bytes = {cls.length_bytes}"
            )
        if length < cls.min_value or length > cls.max_value:
            raise ValueError(
                f"Invalid length {length}: {cls.__name__} can only represent lengths in the range " f"[{cls.min_value}, {cls.max_value}]"
            )
        st = cls.struct_types[cls.length_bytes]
        if not cls.length_signed:
            st = st.upper()
        return struct.pack(f"{cls.length_endianness.value}{st}", length)

    def encode(self) -> bytes:
        body = self.encode_body()
        return self.encode_opcode() + self.encode_length(len(body)) + body

    @classmethod
    def validate(cls, obj):
        length = len(cls(obj).encode_body())
        if length < cls.min_value or length > cls.max_value:
            raise ValueError(
                f"Invalid object {obj!r}: {cls.__name__} can only represent objects with lengths "
                f"in the range [{cls.min_value}, {cls.max_value}]"
            )
        return obj


class NoOp(Opcode):
    def run(self, interpreter: Interpreter):
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
    ConstantOpcodePriorities: dict[type[ConstantOpcode], int] = {}
    priority: int

    def run(self, interpreter: Interpreter):
        interpreter.stack.append(make_constant(self.arg))

    def __init_subclass__(cls, **kwargs):
        ret = super().__init_subclass__(**kwargs)
        if not cls.__name__ == "ConstantInt":
            if cls.validate.__code__ == ConstantOpcode.validate.__code__:
                raise TypeError(f"{cls.__name__} must implement the validate method")
            elif not hasattr(cls, "priority") or not isinstance(cls.priority, int) or cls.priority is None:
                raise TypeError(
                    f"{cls.__name__} must define an integer priority used for auto-instantiation " "from ConstantOpcode.new(...)"
                )
            ConstantOpcode.ConstantOpcodePriorities[cls] = cls.priority
        return ret

    @classmethod
    def validate(cls, obj):
        """
        Validates whether obj can be used to instantiate a new instance of this class using new(...)

        Returning the value of the object to be saved to the constant
        Or throwing a ValueError if obj cannot be used to instantiate this type of constant
        """
        raise NotImplementedError()

    @classmethod
    def new(cls: type[T], obj) -> T:
        for subclass, _ in sorted(ConstantOpcode.ConstantOpcodePriorities.items(), key=lambda kv: kv[1]):
            if not issubclass(subclass, cls):
                continue
            try:
                return subclass(subclass.validate(obj))
            except ValueError:
                pass
        raise ValueError("There is no subclass of ConstantOpcode that handles objects of type " f"{type(obj)!r} for {obj!r}")


class ConstantInt(ConstantOpcode, ABC):
    signed: bool = False
    num_bytes: int = 4
    endianness: Endianness = Endianness.Little
    struct_types = {1: "b", 2: "h", 4: "i", 8: "q"}
    min_value: int
    max_value: int

    def __init_subclass__(cls, **kwargs):
        ret = super().__init_subclass__(**kwargs)
        length_bits = cls.num_bytes * 8
        if cls.signed:
            cls.min_value = 1 << (length_bits - 1)
            cls.max_value = cls.min_value ^ (2**length_bits - 1)
        else:
            cls.min_value = 0
            cls.max_value = 2**length_bits - 1
        return ret

    def encode_body(self) -> bytes:
        st = self.struct_types[self.num_bytes]
        if not self.signed:
            st = st.upper()
        return struct.pack(f"{self.endianness.value}{st}", self.arg)

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, int):
            raise ValueError(f"{cls.__name__} can only be instantiated from integers, not {obj!r}")
        elif cls.num_bytes not in cls.struct_types:
            raise TypeError(f"{cls.__name__}.struct_types does not include a value for " f"{cls.__name__}.length_bytes = {cls.num_bytes}")
        elif obj < cls.min_value or obj > cls.max_value:
            raise ValueError(
                f"Invalid value {obj!r}: {cls.__name__} can only represent lengths in the range " f"[{cls.min_value}, {cls.max_value}]"
            )
        return obj


class StackSliceOpcode(Opcode):
    def run(self, interpreter: Interpreter, stack_slice: list[ast.expr]):
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    def __init_subclass__(cls, **kwargs):
        ret = super().__init_subclass__(**kwargs)
        orig_run = cls.run

        def run_wrapper(self, interpreter: Interpreter):
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
        self.imports: list[ast.Import | ast.ImportFrom] = []
        self.calls: list[ast.Call] = []
        self.non_setstate_calls: list[ast.Call] = []
        self.likely_safe_imports: set[str] = set()

    def _process_import(self, node: ast.Import | ast.ImportFrom):
        self.imports.append(node)
        if isinstance(node, ast.ImportFrom) and is_std_module(node.module):
            self.likely_safe_imports |= {name.name for name in node.names}

    def visit_Import(self, node: ast.Import):  # noqa: N802
        self._process_import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):  # noqa: N802
        self._process_import(node)

    def visit_Call(self, node: ast.Call):  # noqa: N802
        self.calls.append(node)
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "__setstate__":
            self.non_setstate_calls.append(node)


class PickleDecodeError(ValueError):
    pass


class EmptyPickleError(PickleDecodeError):
    pass


class Pickled(OpcodeSequence):
    def __init__(self, opcodes: Iterable[Opcode]):
        self._opcodes: list[Opcode] = list(opcodes)
        self._ast: ast.Module | None = None
        self._properties: ASTProperties | None = None

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

    def _is_constant_type(self, obj: Any) -> bool:
        return isinstance(obj, (int, float, str, bytes))

    def _encode_python_obj(self, obj: Any) -> List[Opcode]:
        """Create an opcode sequence that builds an arbitrary python object on the top of the
        pickle VM stack"""
        if self._is_constant_type(obj):
            return [ConstantOpcode.new(obj)]
        elif isinstance(obj, list):
            res = [Mark()]
            for item in obj:
                if self._is_constant_type(item):
                    res.append(ConstantOpcode.new(item))
                else:
                    res += self._encode_python_obj(item)
            res.append(List())
            return res
        elif isinstance(obj, dict):
            if len(obj) == 0:
                res = [EmptyDict()]
            else:
                res = [Mark()]
                for key, val in obj.items():
                    res.append(ConstantOpcode.new(key))  # Assume key is constant
                    if self._is_constant_type(val):
                        res.append(ConstantOpcode.new(val))
                    else:
                        res += self._encode_python_obj(val)
                res.append(Dict())
            return res
        else:
            raise ValueError(f"Type {type(obj)} not supported")

    def insert_python_obj(self, index: int, obj: Any) -> int:
        """Insert an opcode sequence that constructs a python object on the stack.
        Returns the number of opcodes inserted"""
        opcodes = self._encode_python_obj(obj)
        for i, opcode in enumerate(opcodes):
            self.insert(index + i, opcode)
        return len(opcodes)

    def insert_python(
        self,
        *args,
        module: str = "builtins",
        attr: str = "eval",
        run_first: bool = True,
        use_output_as_unpickle_result: bool = False,
    ) -> int:
        if not isinstance(self[-1], Stop):
            raise ValueError("Expected the last opcode to be STOP")
        # we need to add the call to GLOBAL before the preexisting code, because the following code
        # can sometimes mess up module lookup (somehow? I, Evan, don't fully understand why yet).
        # So we set up the "import" of `__builtin__.eval` first, then set up the stack for a call
        # to it, and then either immediately call the `eval` with a `Reduce` opcode (the default)
        # or optionally insert the `Reduce` at the end (and hope that the existing code cleans up
        # its stack so it remains how we left it!
        # TODO: Add code to emulate the code afterward and confirm that the stack is sane!
        i = 0
        while isinstance(self[i], (Proto, Frame)):
            i += 1
        self.insert(i, Global.create(module, attr))
        i += 1
        self.insert(i, Mark())
        i += 1
        for arg in args:
            i += self.insert_python_obj(i, arg)
            # self.insert(i, ConstantOpcode.new(arg))
            # i += 1
        self.insert(i, Tuple())
        i += 1
        if run_first:
            self.insert(i, Reduce())
            if use_output_as_unpickle_result:
                self.insert(-1, Pop())  # Just discard the original unpickle
            else:
                # At the end, the stack will contain [reduce_res, original_obj].
                # We need to remove everything below original_obj:
                # NOTE(boyan): using an arbitrary MEMO key here seems to work. If not,
                # then switch to using the interpreter() to determine the correct MEMO key to use here
                self.insert(-1, Put(321987))  # Put obj in memo
                self.insert(-1, Pop())  # Pop obj and reduce_res under
                self.insert(-1, Pop())
                self.insert(-1, Get.create(321987))  # Get back obj
            return i + 1
        else:
            # Inject call
            if use_output_as_unpickle_result:
                # the top of the stack should be the original unpickled value, but we can throw
                # that away because we are replacing it with the result of calling eval:
                self.insert(-1, Pop())
                # now the top of the stack should be our original Global, Mark, Unicode,
                # Tuple setup, ready for Reduce:
                self.insert(-1, Reduce())
            else:
                # we need to preserve the "real" output of the preexisting unpickling, which should
                # be at the top of the stack, directly above our Tuple, Unicode, Mark, and Global
                # stack items we added above.
                # So, we have to save the original result to the memo. First, interpret the existing
                # code to see which memo location it would be saved to:
                interpreter = Interpreter(self)
                interpreter.run()
                memo_id = len(interpreter.memory)
                self.insert(-1, Memoize())
                self.insert(-1, Pop())
                self.insert(-1, Reduce())
                self.insert(-1, Pop())
                self.insert(-1, Get.create(memo_id))
            return -1

    insert_python_eval = insert_python

    def append_python(
        self,
        *args,
        module: str = "builtins",
        attr: str = "eval",
        pop_result: bool = False,
    ) -> int:
        """Append python code to run at the end of the pickle.

        :param pop_result: whether to pop the result of the run off the stack. Appends
        a POP instruction if True"""
        if not isinstance(self[-1], Stop):
            raise ValueError("Expected the last opcode to be STOP")
        # NOTE(boyan): this seems to work even without insert GLOBAL at the beginning
        # of the pickle, but see comment in 'insert_python'
        self.insert(-1, Global.create(module, attr))
        self.insert(-1, Mark())
        for arg in args:
            self.insert(-1, ConstantOpcode.new(arg))
        self.insert(-1, Tuple())
        self.insert(-1, Reduce())
        if pop_result:
            self.insert(-1, Pop())

    def insert_magic_int(self, magic: int, index: int = -1):
        """Insert and pop a specific integer value. This is used for persistent
        injections to locate the injection payload in the pickled file. The value
        is artificially added by using a dummy INT + POP combination that doesn't
        affect the stack when executed

        :param magic: magic integer value to add
        :param index: index in opcodes list where to insert the magic"""
        self.insert(index, Int(magic))
        self.insert(-1 if index == -1 else index + 1, Pop())

    def insert_function_call_on_unpickled_object(
        self,
        function_definition: str,
        constant_args: List[Any] | None = None,
        compile_code: bool = False,
    ):
        """Insert and call a function that takes the unpickled object as parameter.

        :param function_definition: a string containing the full python definiton of the function
        to call, including the `def` keyword. The function prototype must be `myfunc(obj)` where
        `obj` is the object being unpickled. The function return value is used as the unpickling
        output.

        :param compile_code: whether the function definition should be precompiled into
        Python bytecode, for increased obfuscation. Note that the function name will still be
        exposed as plaintext sourcecode as this is required to make the function callable through
        a call to (pseudocode) "eval(function_name)".
        """

        if not isinstance(self[-1], Stop):
            raise ValueError("Expected the last opcode to be STOP")

        # Get function name
        fn_match = list(re.match(r"def\s+(.*?)\s*\(", function_definition).groups())
        if not fn_match:
            raise ValueError("Failed to extract function name from function definition")
        function_name = fn_match[0]

        # Insert exec of the function definition in advance
        if compile_code:
            # Compile the function definition
            code_obj = compile(function_definition, "<string>", "exec")
            bytecode = marshal.dumps(code_obj)  # marshal is required to get literal bytes

            # Instructions:
            ## Current stack status: [model]
            ## Add the compiled bytes to the stack, then unmarshal them back into a code object
            self.append_python(bytecode, module="marshal", attr="loads", pop_result=False)
            ## [model, def func]
            ## Slide exec instructions under the function definition on the stack
            self.insert(-1, Put(1))  # Move function def off the stack and into memory
            self.insert(-1, Pop())
            ## [model]
            if not isinstance(self[-1], Stop):  # sanity check akin to the one in append_python
                raise ValueError("Expected the last opcode to be STOP")
            ### NOTE(boyan): this seems to work even without insert GLOBAL at the beginning
            ### of the pickle, but see comment in 'insert_python'
            self.insert(-1, Global.create("builtins", "exec"))
            ## [model, exec]
            self.insert(-1, Mark())
            ## [model, exec, mark]
            self.insert(-1, Get.create(1))  # Place the function def back
            ## [model, exec, mark, def func]
            self.insert(-1, Tuple())
            ## [model, exec, (def func)]
            self.insert(-1, Reduce())
            ## [model, exec return value]
            self.insert(-1, Pop())  # Remove extraneous return value from the stack
            ## [model]
        else:
            ## Current stack status: [model]
            self.append_python(function_definition, attr="exec", pop_result=True)
            ## [model]

        # Eval the function name get the callable object
        # If we inject myfunc() this will return eval(myfunc) which is the myfunc callable object
        self.append_python(function_name, attr="eval")
        # [model, func]

        # At the end of all of the above operations, the stack contains [model, func].
        # We swap them on the stack:
        self.insert(-1, Put(1))  # Put func in memo
        self.insert(-1, Pop())
        # [model]
        self.insert(-1, Put(2))  # Put model in memo
        self.insert(-1, Pop())
        # []
        self.insert(-1, Get.create(1))
        # [func]
        self.insert(-1, Mark())
        # [func, mark]
        self.insert(-1, Get.create(2))
        # [func, mark, model]

        # Add constant arguments
        if constant_args:
            for arg in constant_args:
                self.insert(-1, ConstantOpcode.new(arg))
        # [func, mark, model, arg1, ..., argn]

        # We need to add TUPLE which
        # packs the function arguments from the stack and then call REDUCE, which calls the injected
        # function.
        # Note: precondition says the function must return the final object so no need to save the
        # object before calling reduce.
        self.insert(-1, Tuple())
        # [func, (model, arg1, ..., argn)]
        self.insert(-1, Reduce())
        # [func return value]

    def insert_python_exec(
        self,
        *args,
        run_first: bool = True,
        use_output_as_unpickle_result: bool = False,
    ):
        return self.insert_python(
            *args,
            module="builtins",
            attr="exec",
            run_first=run_first,
            use_output_as_unpickle_result=use_output_as_unpickle_result,
        )

    def __setitem__(self, index: int | slice, item: Opcode | Iterable[Opcode]):
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

    def dumps_partial(self, from_idx: int, to_idx: int) -> bytes:
        """Dump bytecode only between two opcodes

        :param from_idx: index of opcode from which we dump (included)
        :param to_idx: index of opcode until which we dump (included). If -1, dump to end of file
        """
        # Sanity check
        assert from_idx >= 0 and (to_idx >= from_idx or to_idx == -1)

        b = bytearray()
        for opcode in self._opcodes[from_idx:to_idx]:
            b.extend(opcode.data)
        return bytes(b)

    @property
    def opcodes(self) -> Iterator[Opcode]:
        return iter(self)

    @staticmethod
    def make_stream(data: Buffer | BinaryIO) -> BinaryIO:
        if isinstance(data, (bytes, bytearray, Buffer)):
            data = BytesIO(data)
        elif (not hasattr(data, "seekable") or not data.seekable()) and hasattr(data, "read"):
            data = BytesIO(data.read())
        return data

    @staticmethod
    def load(pickled: Buffer | BinaryIO) -> Pickled:
        pickled = Pickled.make_stream(pickled)
        first_pos = pickled.tell()
        opcodes: List[Opcode] = []

        try:
            for info, arg, pos in genops(pickled):
                pos_before = pickled.tell()
                try:
                    if pos is not None and opcodes and opcodes[-1].pos is not None and not opcodes[-1].has_data() and opcodes[-1].pos < pos:
                        pickled.seek(opcodes[-1].pos)
                        opcodes[-1].data = pickled.read(pos - opcodes[-1].pos)
                    if pos is not None:
                        pickled.seek(pos)
                    if info.arg is None or info.arg.n == 0:
                        if pos is not None:
                            data = None
                        else:
                            data = info.code.encode("utf-8")
                    elif info.arg.n > 0 and pos is not None:
                        data = pickled.read(len(info.code) + info.arg.n)
                        if len(data) != len(info.code) + info.arg.n:
                            raise PickleDecodeError(
                                f"Error decoding opcode {info.name} at offset {pos}: "
                                f"Expected {len(info.code) + info.arg.n} bytes of data but only "
                                f"read {len(data)}"
                            )
                    else:
                        data = None
                    opcodes.append(Opcode(info=info, argument=arg, data=data, position=pos))
                finally:
                    # Need to reset the position within the file so as not to confuse genops
                    pickled.seek(pos_before)
        except ValueError as e:
            if opcodes:
                raise PickleDecodeError(e)
            else:
                raise EmptyPickleError()
        if opcodes:
            if opcodes[-1].pos is not None:
                if opcodes[-1].has_data():
                    last_pos = opcodes[-1].pos + len(opcodes[-1].data)
                else:
                    last_pos = opcodes[-1].pos + len(opcodes[-1].info.code)
                pickled.seek(last_pos)
        else:
            pickled.seek(first_pos)
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
        """Checks whether unpickling would cause a call to a function other than
        object.__setstate__"""
        return bool(self.properties.non_setstate_calls)

    def check_safety(self):
        raise WrongMethodError(
            """This method has been removed. Use fickling.analysis.check_safety()
on the Pickled object instead"""
        )

    def is_likely_safe(self):
        raise WrongMethodError("This method has been removed. Use fickling.is_likely_safe() on the pickle file instead")

    def unsafe_imports(self) -> Iterator[ast.Import | ast.ImportFrom]:
        for node in self.properties.imports:
            if node.module in (
                "__builtin__",
                "__builtins__",
                "builtins",
                "os",
                "posix",
                "nt",
                "subprocess",
                "sys",
                "builtins",
                "socket",
            ):
                yield node
            elif "eval" in (n.name for n in node.names):
                yield node

    def non_standard_imports(self) -> Iterator[ast.Import | ast.ImportFrom]:
        for node in self.properties.imports:
            if not is_std_module(node.module):
                yield node

    @property
    def ast(self) -> ast.Module:
        if self._ast is None:
            self._ast = Interpreter.interpret(self)
        return self._ast

    @property
    def nb_opcodes(self) -> int:
        return len(self._opcodes)


class Stack(GenericSequence, Generic[T]):
    def __init__(self, initial_value: Iterable[T] = ()):
        self._stack: List[T] = list(initial_value)
        self.opcode: Opcode | None = None

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> T: ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> GenericSequence: ...

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
    def __init__(self, interpreter: Interpreter):
        self._list: List[ast.stmt] = []
        self.interpreter: Interpreter = interpreter

    def append(self, stmt: ast.stmt):
        lineno = len(self._list) + 1
        if hasattr(stmt, "lineno") and stmt.lineno is not None and stmt.lineno != lineno:
            raise ValueError(f"Statement {stmt} was expected to have line number {lineno} but instead has " f"{stmt.lineno}")
        setattr(stmt, "lineno", lineno)
        self._list.append(stmt)

    def extend(self, stmts: Iterable[ast.stmt]):
        for stmt in stmts:
            self.append(stmt)

    def __iter__(self) -> Iterator[ast.stmt]:
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __getitem__(self, index: int | slice) -> ast.stmt:
        return self._list[index]


class Interpreter:
    def __init__(self, pickled: Pickled, first_variable_id: int = 0, result_variable: str = "result"):
        self.pickled: Pickled = pickled
        self.memory: dict[int, ast.expr] = {}
        self.stack: Stack[ast.expr | MarkObject] = Stack()
        self.module_body: ModuleBody = ModuleBody(self)
        self.result_variable: str = result_variable
        self._module: ast.Module | None = None
        self._var_counter: int = first_variable_id
        self._opcodes: Iterator[Opcode] = iter(pickled)

    @property
    def next_variable_id(self) -> int:
        return self._var_counter

    def to_ast(self) -> ast.Module:
        if self._module is None:
            self.run()
        return self._module

    def unused_assignments(self) -> dict[str, ast.Assign]:
        if self._module is None:
            self.run()
        used: set[str] = set()
        defined: set[str] = set()
        assignments: dict[str, ast.Assign] = {}
        for statement in self.module_body:
            # skip the last statement because it is always used
            if isinstance(statement, ast.Assign):
                if len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id == "result":
                    # this is the return value of the program
                    break
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
                        if target.id in assignments:
                            # this should never happen, since Fickling constructs the AST
                            sys.stderr.write(f"Warning: Duplicate declaration of variable {target.id}\n")
                        assignments[target.id] = statement
                statement = statement.value
            if statement is not None:
                for node in ast.walk(statement):
                    if isinstance(node, ast.Name):
                        used.add(node.id)
        return {varname: assignments[varname] for varname in defined - used}

    def unused_variables(self) -> frozenset[str]:
        return self.unused_assignments().keys()  # type: ignore

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

    def new_variable(self, value: ast.expr, name: str | None = None) -> str:
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

    @staticmethod
    def create(version: int) -> Proto:
        return Proto(version)

    def encode_body(self) -> bytes:
        return bytes([self.version])

    @property
    def version(self) -> int:
        if self.arg is None:
            return 0
        elif isinstance(self.arg, int):
            return self.arg
        else:
            # Endianness shouldn't really matter here because there is only one byte for the version
            return int.from_bytes(self.arg, "big", signed=False)


class Global(Opcode):
    name = "GLOBAL"

    @staticmethod
    def create(module: str, attr: str) -> Global:
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
        if module in ("__builtin__", "__builtins__", "builtins"):
            # no need to emit an import for builtins!
            pass
        else:
            alias = ast.alias(attr)
            interpreter.module_body.append(ast.ImportFrom(module=module, names=[alias], level=0))
        interpreter.stack.append(ast.Name(attr, ast.Load()))

    def encode(self) -> bytes:
        return f"c{self.module}\n{self.attr}\n".encode()


class StackGlobal(NoOp):
    name = "STACK_GLOBAL"

    def run(self, interpreter: Interpreter):
        attr = interpreter.stack.pop()
        module = interpreter.stack.pop()
        if isinstance(module, ast.Constant):
            module = module.value
        if isinstance(attr, ast.Constant):
            attr = attr.value
        if module in ("__builtin__", "__builtins__", "builtins"):
            # no need to emit an import for builtins!
            pass
        else:
            alias = ast.alias(attr)
            interpreter.module_body.append(ast.ImportFrom(module=module, names=[alias], level=0))
        interpreter.stack.append(ast.Name(attr, ast.Load()))


class Inst(StackSliceOpcode):
    name = "INST"

    @staticmethod
    def create(module: str, classname: str) -> Inst:
        return Inst(f"{module} {classname}")

    @property
    def module(self) -> str:
        return next(iter(self.arg.split(" ")))

    @property
    def cls(self) -> str:
        _, classname, *_ = self.arg.split(" ")
        return classname

    def run(self, interpreter: Interpreter, stack_slice: List[ast.expr]):
        module, classname = self.module, self.cls
        if module in ("__builtin__", "__builtins__", "builtins"):
            # no need to emit an import for builtins!
            pass
        else:
            alias = ast.alias(classname)
            interpreter.module_body.append(ast.ImportFrom(module=module, names=[alias], level=0))
        args = ast.Tuple(tuple(stack_slice))
        call = ast.Call(ast.Name(classname, ast.Load()), list(args.elts), [])
        var_name = interpreter.new_variable(call)
        interpreter.stack.append(ast.Name(var_name, ast.Load()))

    def encode(self) -> bytes:
        return f"i{self.module}\n{self.classname}\n".encode()


class Put(Opcode):
    name = "PUT"

    def run(self, interpreter: Interpreter):
        interpreter.memory[self.arg] = interpreter.stack[-1]

    def encode_body(self) -> bytes:
        # Encode memo_id as decimal \n terminated string
        return f"{self.arg}\n".encode()


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


class AddItems(Opcode):
    name = "ADDITEMS"

    def run(self, interpreter: Interpreter):
        to_add = []
        while interpreter.stack:
            obj = interpreter.stack.pop()
            if isinstance(obj, MarkObject):
                break
            to_add.append(obj)
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")
        if not interpreter.stack:
            raise ValueError("Stack was empty; expected a pyset")
        pyset = interpreter.stack.pop()
        if not isinstance(pyset, ast.Set):
            raise ValueError(f"{pyset!r} was expected to be a set-like object with an `add` function")
        pyset.elts.extend(reversed(to_add))


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
        # However, if we just save it to the stack, then it might not make it to the final AST
        # unless the stack value is actually used. So save the result to a temp variable, and then
        # put that on the stack:
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


class PopMark(Opcode):
    name = "POP_MARK"

    def run(self, interpreter: Interpreter):
        objs = []
        while interpreter.stack:
            obj = interpreter.stack.pop()
            if isinstance(obj, MarkObject):
                break
            objs.append(obj)
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")
        return objs


class Obj(Opcode):
    name = "OBJ"

    def run(self, interpreter: Interpreter):
        args = []
        while interpreter.stack:
            arg = interpreter.stack.pop()
            if isinstance(arg, MarkObject):
                break
            args.insert(0, arg)
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")
        kls = args.pop(0)
        # TODO Verify paths for correctness
        if args or hasattr(kls, "__getinitargs__") or not isinstance(kls, type):
            interpreter.stack.append(ast.Call(kls, args, []))
        else:
            interpreter.stack.append(ast.Call(kls, kls, []))


class ShortBinUnicode(DynamicLength, ConstantOpcode):
    name = "SHORT_BINUNICODE"
    priority = 5000
    length_bytes = 1

    @classmethod
    def validate(cls, obj: str) -> bytes:
        if not isinstance(obj, str):
            raise ValueError(f"obj must be of type str, not {obj!r}")
        return super().validate(obj.encode("utf-8"))

    def encode_body(self) -> bytes:
        text = self.arg
        if isinstance(text, str):
            text = text.encode("utf-8")
        return text


class BinUnicode(ShortBinUnicode):
    name = "BINUNICODE"
    priority = ShortBinUnicode.priority + 1
    length_bytes = 4


class BinUnicode8(BinUnicode):
    name = "BINUNICODE8"
    priority = BinUnicode.priority + 1
    length_bytes = 8


class Unicode(ConstantOpcode):
    name = "UNICODE"
    priority = BinUnicode8.priority + 1

    @classmethod
    def validate(cls, obj: str) -> bytes:
        if not isinstance(obj, str):
            raise ValueError(f"{cls.__name__}.new expects a str object, not {obj!r}")
        return obj.encode("utf-8")

    def encode_body(self) -> bytes:
        return raw_unicode_escape(self.arg).encode("utf-8")


class String(ConstantOpcode):
    name = "STRING"
    priority = Unicode.priority + 1

    def encode_body(self) -> bytes:
        return repr(self.arg).encode("utf-8")

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, str):
            raise ValueError(f"String must be instantiated from a str, not {obj!r}")
        return obj


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
            ast.Call(
                ast.Attribute(ast.Name("UNPICKLER", ast.Load()), "persistent_load"),
                [pid],
                [],
            )
        )


class PersId(Opcode):
    name = "PERSID"


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
        interpreter.module_body.append(
            ast.Expr(
                ast.Call(
                    ast.Attribute(ast.Name(obj_name, ast.Load()), "__setstate__"),
                    [argument],
                    [],
                )
            )
        )
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

    def encode_body(self) -> bytes:
        return f"{self.memo_id}\n".encode()

    @staticmethod
    def create(memo_id: int) -> Get:
        return Get(f"{memo_id}\n".encode())


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
            interpreter.module_body.append(
                ast.Expr(
                    ast.Call(
                        ast.Attribute(ast.Name(dict_name, ast.Load()), "update"),
                        [update_dict],
                        [],
                    )
                )
            )
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
            assignment = ast.Assign(
                [ast.Subscript(ast.Name(dict_name, ast.Load()), key, ast.Store())],
                value,
            )
            interpreter.module_body.append(assignment)
            interpreter.stack.append(ast.Name(dict_name, ast.Load()))


class Stop(Opcode):
    name = "STOP"

    def run(self, interpreter: Interpreter):
        interpreter.new_variable(interpreter.stack.pop(), name=interpreter.result_variable)
        interpreter.stop()


class Frame(NoOp):
    name = "FRAME"


class BinInt1(ConstantInt):
    name = "BININT1"
    priority = 100
    num_bytes = 1


class BinInt2(BinInt1):
    name = "BININT2"
    priority = BinInt1.priority + 1
    num_bytes = 2


class BinInt(ConstantInt):
    name = "BININT"
    priority = BinInt2.priority + 1
    num_bytes = 4
    signed = True


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


class Append(Opcode):
    name = "APPEND"

    def run(self, interpreter: Interpreter):
        value = interpreter.stack.pop()
        list_obj = interpreter.stack[-1]
        if isinstance(list_obj, ast.List):
            list_obj.elts.append(value)
        else:
            raise ValueError(f"Expected a list on the stack, but instead found {list_obj!r}")


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
    priority = BinInt1.priority * 2

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, float):
            raise ValueError(f"{cls.__name__} expects a float, but received {obj!r}")
        return obj


class ShortBinBytes(DynamicLength, ConstantOpcode):
    name = "SHORT_BINBYTES"
    priority = Unicode.priority + 1
    length_bytes = 1

    def encode_body(self) -> bytes:
        return self.arg

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, bytes):
            raise ValueError(f"{cls.__name__} must be instantiated with an object of type bytes, not {obj!r}")
        return super().validate(obj)


class ShortBinString(DynamicLength, ConstantOpcode):
    name = "SHORT_BINSTRING"
    priority = Unicode.priority + 1
    length_bytes = 1

    def encode_body(self) -> bytes:
        return repr(self.arg).encode("utf-8")

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, str):
            raise ValueError(f"String must be instantiated from a str, not {obj!r}")
        return obj


class BinString(DynamicLength, ConstantOpcode):
    name = "BINSTRING"
    priority = ShortBinBytes.priority + 1
    length_bytes = 4
    signed = True

    def encode_body(self) -> bytes:
        return repr(self.arg).encode("utf-8")

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, str):
            raise ValueError(f"String must be instantiated from a str, not {obj!r}")
        return super().validate(obj)


class BinBytes(ShortBinBytes):
    name = "BINBYTES"
    priority = ShortBinBytes.priority + 1
    length_bytes = 4


class BinBytes8(BinBytes):
    name = "BINBYTES8"
    priority = BinBytes.priority + 1
    length_bytes = 8


class Long1(ConstantInt):
    name = "LONG1"
    num_bytes = 1
    signed = True
    priority = BinInt.priority + 1


class Long4(ConstantInt):
    name = "LONG4"
    num_bytes = 4
    signed = True
    priority = Long1.priority + 1


class Int(ConstantOpcode):
    name = "INT"
    priority = Long4.priority + 1

    def encode_body(self) -> bytes:
        return f"{int(self.arg)}\n".encode()

    @classmethod
    def validate(cls, obj):
        _ = int(obj)
        return obj


class Long(Int):
    name = "LONG"
    priority = Int.priority + 1


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

        interpreter.stack.append(ast.Dict(keys=reversed(keys), values=reversed(values)))


PickledSequence = Sequence[Pickled]


class StackedPickle(PickledSequence):
    def __init__(self, pickled: Iterable[Pickled]):
        self.pickled: tuple[Pickled, ...] = tuple(pickled)

    def __getitem__(self, index: int) -> Pickled:
        return self.pickled[index]

    def __len__(self) -> int:
        return len(self.pickled)

    @staticmethod
    def load(pickled: Buffer | BinaryIO) -> StackedPickle:
        pickled = Pickled.make_stream(pickled)
        pickles: List[Pickled] = []
        while True:
            try:
                p = Pickled.load(pickled)
                if len(p) == 0:
                    break
                pickles.append(p)
            except EmptyPickleError:
                break
        if not pickles:
            raise EmptyPickleError("No pickle files detected")
        return StackedPickle(pickles)


class List(Opcode):
    name = "LIST"

    def run(self, interpreter: Interpreter):
        objs = []
        while interpreter.stack:
            obj = interpreter.stack.pop()
            if isinstance(obj, MarkObject):
                break
            objs.append(obj)
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")

        interpreter.stack.append(ast.List(elts=objs[::-1], ctx=ast.Load()))


class FrozenSet(Opcode):
    name = "FROZENSET"

    def run(self, interpreter: Interpreter):
        objs = []
        while interpreter.stack:
            obj = interpreter.stack.pop()
            if isinstance(obj, MarkObject):
                break
            objs.append(obj)
        else:
            raise ValueError("Exhausted the stack while searching for a MarkObject!")

        interpreter.stack.append(ast.Constant(ast.Set(elts=objs[::-1])))


class Dup(Opcode):
    name = "DUP"

    def run(self, interpreter: Interpreter):
        stack_len = len(interpreter.stack)
        if stack_len == 0:
            raise IndexError(
                f"Opcode {self.opcode!s} \
                attempted to duplicate the topmost entry on the stack, but it is empty"
            )
        obj = interpreter.stack[stack_len - 1]
        interpreter.stack.append(obj)
