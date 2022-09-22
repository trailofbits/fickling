import ast
from enum import Enum
import sys
from typing import Iterable, Iterator, List, Optional, Set, Tuple

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from .pickle import Opcode, Pickled, Proto, Interpreter


class PickleLocation:
    pass


class OpcodeLocation(PickleLocation):
    def __init__(self, opcode: Opcode):
        self.opcode: Opcode = opcode

    def __hash__(self):
        return hash(self.opcode.pos)

    def __eq__(self, other):
        return isinstance(other, OpcodeLocation) and other.opcode.pos == self.opcode.pos and other.opcode == self.opcode

    def __lt__(self, other):
        if isinstance(other, OpcodeLocation):
            return self.opcode < other.opcode
        elif isinstance(other, ASTLocation):
            return not (other < self)
        else:
            return True

    def __str__(self):
        if self.opcode.pos is not None:
            return f"opcode {self.opcode!s}"


class ASTLocation(PickleLocation):
    def __init__(self, ast_node):
        self.ast_node = ast_node
        self._code: Optional[str] = None
        self._shortened: Optional[str] = None
        self._str: Optional[str] = None

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return isinstance(other, ASTLocation) and str(other) == str(self)

    def __lt__(self, other):
        if isinstance(other, OpcodeLocation):
            return all(op.opcode < other.opcode for op in self.opcodes)
        elif isinstance(other, ASTLocation):
            if not self.opcodes or not other.opcodes:
                return str(self) < str(other)
            my_min_opcode = min(op.opcode for op in self.opcodes)
            their_min_opcode = min(op.opcode for op in other.opcodes)
            return my_min_opcode < their_min_opcode
        else:
            return True

    @property
    def code(self) -> str:
        if self._code is None:
            self._code = unparse(self.ast_node).strip()
        return self._code

    @property
    def shortened(self) -> str:
        if self._shortened is None:
            code = self.code
            if len(code) > 32:
                cutoff = code.find("(")
                if code[cutoff] == "(":
                    return f"{code[:code.find('(')].strip()}(...)"
            self._shortened = code
        return self._shortened

    @property
    def opcodes(self) -> Set[OpcodeLocation]:
        return {
            OpcodeLocation(node.opcode)
            for node in ast.walk(self.ast_node) if hasattr(node, "opcode") and node.opcode is not None
        }

    def __str__(self):
        if self._str is None:
            opcodes = sorted(self.opcodes, key=lambda o: o.index)
            if len(opcodes) == 1:
                self._str = f"{opcodes[0]!s}: {self.shortened}"
            elif len(opcodes) == 0:
                self._str = self.shortened
            elif len(opcodes) == 2:
                self._str = f"opcodes {opcodes[0]!s} and {opcodes[1]!s}: {self.shortened}"
            else:
                self._str = f"opcodes {', '.join(map(str, opcodes[:-1]))}, and {opcodes[-1]!s}: {self.shortened}"
        return self._str


class Safety(Enum):
    LIKELY_SAFE = 0
    SUSPICIOUS = 1
    UNSAFE = 2


class AnalysisResult:
    def __init__(self, message: str, safety: Safety, location: PickleLocation):
        self.message: str = message
        self.safety: Safety = safety
        self.location: PickleLocation = location

    def __lt__(self, other):
        return not isinstance(other, AnalysisResult) or self.safety.value > other.safety.value or \
               self.location < other.location


class Results:
    def __init__(self, results: Iterable[AnalysisResult] = ()):
        self.results: Tuple[AnalysisResult, ...] = tuple(sorted(results))

    def __iter__(self) -> Iterator[AnalysisResult]:
        return iter(self.results)

    def __add__(self, other) -> "Results":
        if isinstance(other, AnalysisResult):
            return Results(self.results + (other,))
        return Results(self.results + tuple(other))

    @property
    def safety(self) -> Safety:
        if not self.results:
            return Safety.LIKELY_SAFE
        return max([r.safety for r in self.results], key=lambda s: s.value)

    def __getitem__(self, item) -> AnalysisResult:
        return self.results[item]

    def __len__(self):
        return len(self.results)

    def __bool__(self):
        return self.safety == Safety.LIKELY_SAFE

    def __str__(self):
        if len(self) == 0:
            return "Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may " \
                   "still be unsafe.\n\nDo not unpickle this file if it is from an untrusted source!"
        return "\n".join(map(str, self))


def check_safety(pickled: Pickled) -> Results:
    properties = pickled.properties
    results: List[AnalysisResult] = []

    had_proto = False
    proto_versions: Set[int] = set()
    for i, opcode in enumerate(pickled):
        if isinstance(opcode, Proto):
            if had_proto:
                if opcode.version in proto_versions:
                    results.append(AnalysisResult(
                        message="duplicate PROTO, which is unusual and may be indicative of a tampered pickle",
                        safety=Safety.SUSPICIOUS,
                        location=OpcodeLocation(opcode)
                    ))
                else:
                    results.append(AnalysisResult(
                        message="duplicate PROTO with a different version than reported in the previous PROTO opcode, "
                                "which is almost certainly a sign of a tampered pickle",
                        safety=Safety.UNSAFE,
                        location=OpcodeLocation(opcode)
                    ))
            else:
                had_proto = True
            if opcode.version >= 2 and i > 0:
                results.append(AnalysisResult(
                    message=f"The protocol version is {opcode.version}, but the PROTO opcode is not the first opcode "
                            f"in the pickle, as required for versions 2 and later; this may be indicative of a "
                            f"tampered pickle",
                    safety=Safety.UNSAFE,
                    location=OpcodeLocation(opcode)
                ))
            proto_versions.add(opcode.version)

    for node in pickled.non_standard_imports():
        results.append(AnalysisResult(
            message="import of a Python module that is not a part of the standard library, or that can be used to "
                    "execute arbitrary code; this is inherently unsafe",
            safety=Safety.UNSAFE,
            location=ASTLocation(node)
        ))

    for node in properties.non_setstate_calls:
        if hasattr(node.func, "id") and node.func.id in properties.likely_safe_imports:
            # if the call is to a constructor of an object imported from the Python standard library,
            # it's probably okay
            continue
        location = ASTLocation(node)
        if (
                location.code.startswith("eval(") or
                location.code.startswith("exec(") or
                location.code.startswith("compile(") or
                location.code.startswith("open(")
        ):
            # this is overtly bad
            results.append(AnalysisResult(
                message="function call is almost certainly evidence of a malicious pickle file",
                safety=Safety.UNSAFE,
                location=location
            ))
        else:
            results.append(AnalysisResult(
                message="function call can execute arbitrary code and is inherently unsafe",
                safety=Safety.SUSPICIOUS,
                location=location
            ))
    for node in pickled.unsafe_imports():
        results.append(AnalysisResult(
            message="this import is suspicious and indicative of an overtly malicious pickle file",
            safety=Safety.UNSAFE,
            location=ASTLocation(node)
        ))
    interpreter = Interpreter(pickled)
    for varname, asmt in interpreter.unused_assignments().items():
        results.append(AnalysisResult(
            message=f"Variable `{varname}` is assigned value `{ASTLocation(asmt.value).shortened}` but unused "
                    f"afterward; this is suspicious and indicative of a malicious pickle file",
            safety=Safety.SUSPICIOUS,
            location=ASTLocation(asmt)
        ))

    return Results(results)
