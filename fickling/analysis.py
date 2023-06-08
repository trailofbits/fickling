import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from typing import Dict, Iterable, Iterator, Optional, Set, TextIO, Tuple, Type

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from .fickle import Interpreter, List, Pickled, Proto


class AnalyzerMeta(type):
    _DEFAULT_INSTANCE: Optional["Analyzer"] = None

    @property
    def default_instance(cls) -> "Analyzer":
        if cls._DEFAULT_INSTANCE is None:
            cls._DEFAULT_INSTANCE = Analyzer(Analysis.ALL)
        return cls._DEFAULT_INSTANCE


class AnalysisContext:
    def __init__(self, pickled: Pickled):
        self.pickled: Pickled = pickled
        self.reported_shortened_code: Set[str] = set()
        self.previous_results: List[AnalysisResult] = []
        self.results_by_analysis: Dict[Type[Analysis], List[AnalysisResult]] = defaultdict(list)

    def analyze(self, analysis: "Analysis") -> "List[AnalysisResult]":
        results = list(analysis.analyze(self))
        if not results:
            self.results_by_analysis[type(analysis)].append(AnalysisResult(Severity.LIKELY_SAFE))
        else:
            self.previous_results.extend(results)
            self.results_by_analysis[type(analysis)].extend(results)
        return results

    @property
    def results(self) -> "AnalysisResults":
        return AnalysisResults(pickled=self.pickled, results=self.previous_results)

    def shorten_code(self, ast_node) -> Tuple[str, bool]:
        code = unparse(ast_node).strip()
        if len(code) > 32:
            cutoff = code.find("(")
            if code[cutoff] == "(":
                shortened_code = f"{code[:code.find('(')].strip()}(...)"
            else:
                shortened_code = code
        else:
            shortened_code = code
        was_already_reported = shortened_code in self.reported_shortened_code
        self.reported_shortened_code.add(shortened_code)
        return shortened_code, was_already_reported


class Analyzer(metaclass=AnalyzerMeta):
    def __init__(self, analyses: Iterable["Analysis"]):
        self.analyses: Tuple[Analysis, ...] = tuple(analyses)

    def analyze(self, pickled: Pickled) -> "AnalysisResults":
        context = AnalysisContext(pickled=pickled)
        for a in self.analyses:
            context.analyze(a)
        return context.results


class Severity(Enum):
    LIKELY_SAFE = (0, "No Unsafe Operations Discovered")
    UNKNOWN = (1, "Unknown")
    SUSPICIOUS = (2, "Suspicious")
    LIKELY_UNSAFE = (3, "Likely Unsafe")
    LIKELY_OVERTLY_MALICIOUS = (4, "Likely Overtly Malicious")
    OVERTLY_MALICIOUS = (5, "Overtly Malicious")

    def __lt__(self, other):
        return isinstance(other, Severity) and self.value < other.value

    def __gt__(self, other):
        return not isinstance(other, Severity) or other < self

    def __eq__(self, other):
        return isinstance(other, Severity) and other.value == self.value

    def __ge__(self, other):
        return self > other or self == other

    def __le__(self, other):
        return self < other or self == other

    def __init__(self, severity: int, message: str):
        self.severity: int = severity
        self.message: str = message


class AnalysisResult:
    def __init__(self, severity: Severity, message: Optional[str] = None):
        self.severity: Severity = severity
        self.message: Optional[str] = message

    def __lt__(self, other):
        return isinstance(other, AnalysisResult) and (
            self.severity < other.severity
            or (self.severity == other.severity and str(self) < str(other))
        )

    def __bool__(self):
        """Returns True if there is no evidence that this result is unsafe"""
        return self.severity == Severity.LIKELY_SAFE

    def __str__(self):
        if self.message is None:
            return ""
        else:
            return self.message


class Analysis(ABC):
    ALL: "List[Analysis]" = []

    def __init_subclass__(cls, **kwargs):
        Analysis.ALL.append(cls())

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        raise NotImplementedError()


class ProtoAnalysis(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        had_proto = False
        proto_versions: Set[int] = set()
        for i, opcode in enumerate(context.pickled):
            if isinstance(opcode, Proto):
                if had_proto:
                    if i == 2:
                        suffix = "rd"
                    elif i == 1:
                        suffix = "nd"
                    elif i == 0:
                        suffix = "st"
                    else:
                        suffix = "th"
                    if opcode.version in proto_versions:
                        yield AnalysisResult(
                            Severity.LIKELY_UNSAFE,
                            f"The {i + 1}{suffix} opcode is a duplicate PROTO, which is unusual "
                            f"and may be indicative of a tampered pickle",
                        )
                    else:
                        yield AnalysisResult(
                            Severity.LIKELY_UNSAFE,
                            f"The {i + 1}{suffix} opcode is a duplicate PROTO with a different "
                            f"version than reported in the previous PROTO opcode, which is almost "
                            f"certainly a sign of a tampered pickle",
                        )
                else:
                    had_proto = True
                if opcode.version >= 2 and i > 0:
                    yield AnalysisResult(
                        Severity.LIKELY_UNSAFE,
                        f"The protocol version is {opcode.version}, but the PROTO opcode is not "
                        f"the first opcode in the pickle, as required for versions 2 and later; "
                        f"this may be indicative of a tampered pickle",
                    )
                proto_versions.add(opcode.version)


class NonStandardImports(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.non_standard_imports():
            shortened, already_reported = context.shorten_code(node)
            if not already_reported:
                yield AnalysisResult(
                    Severity.LIKELY_UNSAFE,
                    f"`{shortened}` imports a Python module that is not a part of "
                    "the standard library; this can execute arbitrary code and is "
                    "inherently unsafe",
                )


class OvertlyBadEvals(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.non_setstate_calls:
            if (
                hasattr(node.func, "id")
                and node.func.id in context.pickled.properties.likely_safe_imports
            ):
                # if the call is to a constructor of an object imported from the Python
                # standard library, it's probably okay
                continue
            shortened, already_reported = context.shorten_code(node)
            if (
                shortened.startswith("eval(")
                or shortened.startswith("exec(")
                or shortened.startswith("compile(")
                or shortened.startswith("open(")
            ):
                # this is overtly bad, so record it and print it at the end
                yield AnalysisResult(
                    Severity.OVERTLY_MALICIOUS,
                    f"Call to `{shortened}` is almost certainly evidence of a "
                    "malicious pickle file",
                )
            elif not already_reported:
                yield AnalysisResult(
                    Severity.LIKELY_UNSAFE,
                    f"Call to `{shortened}` can execute arbitrary code and is inherently unsafe",
                )


class UnsafeImports(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.unsafe_imports():
            shortened, _ = context.shorten_code(node)
            yield AnalysisResult(
                Severity.LIKELY_OVERTLY_MALICIOUS,
                f"`{shortened}` is suspicious and indicative of an overtly malicious pickle file",
            )


class UnusedVariables(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        interpreter = Interpreter(context.pickled)
        for varname, asmt in interpreter.unused_assignments().items():
            shortened, _ = context.shorten_code(asmt.value)
            yield AnalysisResult(
                Severity.SUSPICIOUS,
                f"Variable `{varname}` is assigned value `{shortened}` but unused afterward; "
                f"this is suspicious and indicative of a malicious pickle file",
            )


class AnalysisResults:
    def __init__(self, pickled: Pickled, results: Iterable[AnalysisResult]):
        self.pickled: Pickled = pickled
        self.results: Tuple[AnalysisResult, ...] = tuple(results)

    @property
    def severity(self) -> Severity:
        if not self.results:
            return Severity.UNKNOWN
        return max(r.severity for r in self.results)

    def __bool__(self):
        """Returns True if all analyses failed to find any unsafe operations"""
        return all(map(bool, sorted(self.results)))

    def to_string(self, verbosity: Severity = Severity.SUSPICIOUS):
        return "\n".join(str(r) for r in self.results if verbosity <= r.severity)

    __str__ = to_string


def check_safety(
    pickled: Pickled,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    analyzer: Optional[Analyzer] = None,
    verbosity: Severity = Severity.SUSPICIOUS,
) -> AnalysisResults:
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr

    if analyzer is None:
        analyzer = Analyzer.default_instance

    results = analyzer.analyze(pickled)

    stdout.write(results.to_string(verbosity))

    if results.severity >= Severity.LIKELY_SAFE:
        stderr.write(
            "Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may "
            "still be unsafe.\n\nDo not unpickle this file if it is from an untrusted source!\n"
        )

    return results
