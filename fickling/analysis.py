from __future__ import annotations

import json
from abc import ABC, abstractmethod
from ast import unparse
from collections import defaultdict
from collections.abc import Iterable, Iterator
from enum import Enum

from fickling.fickle import Interpreter, Pickled, Proto


class AnalyzerMeta(type):
    _DEFAULT_INSTANCE: Analyzer | None = None

    @property
    def default_instance(cls) -> Analyzer:
        if cls._DEFAULT_INSTANCE is None:
            cls._DEFAULT_INSTANCE = Analyzer(Analysis.ALL)
        return cls._DEFAULT_INSTANCE


class AnalysisContext:
    def __init__(self, pickled: Pickled):
        self.pickled: Pickled = pickled
        self.reported_shortened_code: set[str] = set()
        self.previous_results: list[AnalysisResult] = []
        self.results_by_analysis: dict[type[Analysis], list[AnalysisResult]] = defaultdict(list)

    def analyze(self, analysis: Analysis) -> list[AnalysisResult]:
        results = list(analysis.analyze(self))
        if not results:
            self.results_by_analysis[type(analysis)].append(AnalysisResult(Severity.LIKELY_SAFE))
        else:
            self.previous_results.extend(results)
            self.results_by_analysis[type(analysis)].extend(results)
        return results

    @property
    def results(self) -> AnalysisResults:
        return AnalysisResults(pickled=self.pickled, results=self.previous_results)

    def shorten_code(self, ast_node) -> tuple[str, bool]:
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
    def __init__(self, analyses: Iterable[Analysis]):
        self.analyses: tuple[Analysis, ...] = tuple(analyses)

    def analyze(self, pickled: Pickled) -> AnalysisResults:
        context = AnalysisContext(pickled=pickled)
        for a in self.analyses:
            context.analyze(a)
        return context.results


class Severity(Enum):
    LIKELY_SAFE = (0, "No Unsafe Operations Discovered")
    POSSIBLY_UNSAFE = (1, "Possibly Unsafe")
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
    def __init__(
        self,
        severity: Severity,
        message: str | None = None,
        analysis_name: str = None,
        trigger: str | None = None,
    ):
        self.severity: Severity = severity
        self.message: str | None = message
        self.analysis_name: str = analysis_name
        self.trigger: str | None = trigger  # Field to store the trigger code fragment or artifact

    def __lt__(self, other):
        return isinstance(other, AnalysisResult) and (
            self.severity < other.severity or (self.severity == other.severity and str(self) < str(other))
        )

    def __bool__(self):
        """Returns True if there is no evidence that this result is unsafe"""
        return self.severity == Severity.LIKELY_SAFE

    def __str__(self):
        if self.message is None:
            return "No issues found"
        else:
            return self.message


class Analysis(ABC):
    ALL: list[Analysis] = []

    def __init_subclass__(cls, **kwargs):
        Analysis.ALL.append(cls())

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        raise NotImplementedError()


class DuplicateProtoAnalysis(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        had_proto = False
        proto_versions: set[int] = set()
        for i, opcode in enumerate(context.pickled):
            if isinstance(opcode, Proto):
                if had_proto:
                    suffix = self._get_suffix(i)
                    if opcode.version in proto_versions:
                        yield AnalysisResult(
                            Severity.LIKELY_UNSAFE,
                            f"The {i + 1}{suffix} opcode is a duplicate PROTO, which is unusual "
                            f"and may be indicative of a tampered pickle",
                            "DuplicateProtoAnalysis",
                            trigger=i + 1,
                        )
                    else:
                        yield AnalysisResult(
                            Severity.LIKELY_UNSAFE,
                            f"The {i + 1}{suffix} opcode is a duplicate PROTO with a different "
                            f"version than reported in the previous PROTO opcode, which is almost "
                            f"certainly a sign of a tampered pickle",
                            "DuplicateProtoAnalysis",
                            trigger=i + 1,
                        )
                else:
                    had_proto = True
                proto_versions.add(opcode.version)

    @staticmethod
    def _get_suffix(index: int) -> str:
        return {0: "st", 1: "nd", 2: "rd"}.get(index, "th")


class MisplacedProtoAnalysis(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for i, opcode in enumerate(context.pickled):
            if isinstance(opcode, Proto):
                if opcode.version >= 2 and i > 0:
                    yield AnalysisResult(
                        Severity.LIKELY_UNSAFE,
                        f"The protocol version is {opcode.version}, but the PROTO opcode is not "
                        f"the first opcode in the pickle, as required for versions 2 and later; "
                        f"this may be indicative of a tampered pickle",
                        "MisplacedProtoAnalysis",
                        trigger=opcode.version,
                    )


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
                    "NonStandardImports",
                    trigger=shortened,
                )


class UnsafeImportsML(Analysis):
    UNSAFE_MODULES = {
        "__builtin__": "This module contains dangerous functions that can execute arbitrary code.",
        "__builtins__": "This module contains dangerous functions that can execute arbitrary code.",
        "builtins": "This module contains dangerous functions that can execute arbitrary code.",
        "os": "This module contains functions that can perform system operations and execute arbitrary code.",
        "posix": "This module contains functions that can perform system operations and execute arbitrary code.",
        "nt": "This module contains functions that can perform system operations and execute arbitrary code.",
        "subprocess": "This module contains functions that can run arbitrary executables and perform system operations.",
        "sys": "This module can tamper with the python interpreter.",
        "socket": "This module gives access to low-level socket interfaces and can initiate dangerous network connections.",
        "shutil": "This module contains functions that can perform system operations and execute arbitrary code.",
        "urllib": "This module can use HTTP to leak local data and download malicious files.",
        "urllib2": "This module can use HTTP to leak local data and download malicious files.",
        "torch.hub": "This module can load untrusted files from the web, exposing the system to arbitrary code execution.",
        "dill": "This module can load and execute arbitrary code.",
        "code": "This module can compile and execute arbitrary code.",
    }

    UNSAFE_IMPORTS = {
        "torch": {"load": "This function can load untrusted files and code from arbitrary web sources."},
        "numpy.testing._private.utils": {"runstring": "This function can execute arbitrary code."},
        "operator": {
            "getitem": "This function can lead to arbitrary code execution",
            "attrgetter": "This function can lead to arbitrary code execution",
            "itemgetter": "This function can lead to arbitrary code execution",
            "methodcaller": "This function can lead to arbitrary code execution",
        },
        "torch.storage": {
            "_load_from_bytes": "This function calls `torch.load()` which is unsafe as using a string argument would "
            "allow to load and execute arbitrary code hosted on the internet. However, in this case, the "
            "argument is explicitly converted to `io.bytesIO` and hence treated as a bytestream and not as "
            "a remote URL. However, a malicious file can supply a pickle opcode bytestring as argument to this function to cause the "
            "underlying `torch.load()` call to unpickle that bytestring and execute arbitrary code through nested pickle calls. "
            "So this import is safe only if restrictions on pickle (such as Fickling's hooks) have been set properly",
        },
    }

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.imports:
            shortened, _ = context.shorten_code(node)
            all_modules = [node.module.rsplit(".", i)[0] for i in range(0, node.module.count(".") + 1)]
            for module_name in all_modules:
                if module_name in self.UNSAFE_MODULES:
                    risk_info = self.UNSAFE_MODULES[module_name]
                    yield AnalysisResult(
                        Severity.LIKELY_OVERTLY_MALICIOUS,
                        f"`{shortened}` uses `{module_name}` that is indicative of a malicious pickle file. {risk_info}",
                        "UnsafeImportsML",
                        trigger=shortened,
                    )
            if node.module in self.UNSAFE_IMPORTS:
                for n in node.names:
                    if n.name in self.UNSAFE_IMPORTS[node.module]:
                        risk_info = self.UNSAFE_IMPORTS[node.module][n.name]
                        yield AnalysisResult(
                            Severity.LIKELY_OVERTLY_MALICIOUS,
                            f"`{shortened}` imports `{n.name}` that is indicative of a malicious pickle file. {risk_info}",
                            "UnsafeImportsML",
                            trigger=shortened,
                        )
            # NOTE(boyan): Special case with eval?
            # Copy pasted from pickled.unsafe_imports() original implementation
            elif "eval" in (n.name for n in node.names):
                yield node


class BadCalls(Analysis):
    BAD_CALLS = ["exec", "eval", "compile", "open"]

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.calls:
            shortened, already_reported = context.shorten_code(node)
            if any(shortened.startswith(f"{c}(") for c in self.BAD_CALLS):
                yield AnalysisResult(
                    Severity.OVERTLY_MALICIOUS,
                    f"Call to `{shortened}` is almost certainly evidence of a " "malicious pickle file",
                    "OvertlyBadEval",
                    trigger=shortened,
                )


class OvertlyBadEvals(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.non_setstate_calls:
            if hasattr(node.func, "id") and node.func.id in context.pickled.properties.likely_safe_imports:
                # if the call is to a constructor of an object imported from the Python
                # standard library, it's probably okay
                continue
            shortened, already_reported = context.shorten_code(node)
            if (
                shortened.startswith("eval(")
                or shortened.startswith("exec(")
                or shortened.startswith("compile(")
                or shortened.startswith("open(")
                or shortened.startswith("_run_code(")
                or shortened.startswith("execWrapper(")
            ):
                # this is overtly bad, so record it and print it at the end
                yield AnalysisResult(
                    Severity.OVERTLY_MALICIOUS,
                    f"Call to `{shortened}` is almost certainly evidence of a " "malicious pickle file",
                    "OvertlyBadEval",
                    trigger=shortened,
                )
            elif not already_reported:
                yield AnalysisResult(
                    Severity.LIKELY_UNSAFE,
                    f"Call to `{shortened}` can execute arbitrary code and is inherently unsafe",
                    "OvertlyBadEval",
                    trigger=shortened,
                )


class UnsafeImports(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.unsafe_imports():
            shortened, _ = context.shorten_code(node)
            yield AnalysisResult(
                Severity.LIKELY_OVERTLY_MALICIOUS,
                f"`{shortened}` is suspicious and indicative of an overtly malicious pickle file",
                "UnsafeImports",
                trigger=shortened,
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
                "UnusedVariables",
                trigger=(varname, shortened),
            )


class AnalysisResults:
    def __init__(self, pickled: Pickled, results: Iterable[AnalysisResult]):
        self.pickled: Pickled = pickled
        self.results: tuple[AnalysisResult, ...] = tuple(results)

    @property
    def severity(self) -> Severity:
        if not self.results:
            return Severity.LIKELY_SAFE
        return max(r.severity for r in self.results)

    def __bool__(self):
        """Returns True if all analyses failed to find any unsafe operations"""
        return all(map(bool, sorted(self.results)))

    def detailed_results(self) -> dict[str, dict[str, str]]:
        detailed = defaultdict(dict)
        for result in self.results:
            if result.trigger:
                detailed["AnalysisResult"][result.analysis_name] = result.trigger
        return dict(detailed)

    def to_string(self, verbosity: Severity = Severity.POSSIBLY_UNSAFE):
        return "\n".join(str(r) for r in self.results if verbosity <= r.severity)

    __str__ = to_string

    def to_dict(self, verbosity: Severity = Severity.POSSIBLY_UNSAFE):
        analysis_message = self.to_string(verbosity)
        severity_data = {
            "severity": self.severity.name,
            "analysis": (
                analysis_message
                if analysis_message.strip()
                else "Warning: Fickling failed to detect any overtly unsafe code,"
                "but the pickle file may still be unsafe."
                "Do not unpickle this file if it is from an untrusted source!\n\n"
            ),
            "detailed_results": self.detailed_results(),
        }
        return severity_data


def check_safety(
    pickled: Pickled,
    analyzer: Analyzer | None = None,
    verbosity: Severity = Severity.POSSIBLY_UNSAFE,
    json_output_path: str | None = None,
) -> AnalysisResults:
    if analyzer is None:
        analyzer = Analyzer.default_instance

    results = analyzer.analyze(pickled)
    severity_data = results.to_dict(verbosity)
    if json_output_path:
        # This is intentionally "a" to handle the case of stacked pickles
        with open(json_output_path, "a") as json_file:
            json.dump(severity_data, json_file, indent=4)
    return results


def is_likely_safe(filepath: str):
    with open(filepath, "rb") as f:
        return check_safety(Pickled.load(f)).severity == Severity.LIKELY_SAFE
