import json
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Type

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from fickling.fickle import Interpreter, Pickled, Proto

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
    SUSPICIOUS = (1, "Suspicious")
    LIKELY_UNSAFE = (2, "Likely Unsafe")
    LIKELY_OVERTLY_MALICIOUS = (3, "Likely Overtly Malicious")
    OVERTLY_MALICIOUS = (4, "Overtly Malicious")

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
        message: Optional[str] = None,
        analysis_name: str = None,
        trigger: Optional[str] = None,
    ):
        self.severity: Severity = severity
        self.message: Optional[str] = message
        self.analysis_name: str = analysis_name
        self.trigger: Optional[str] = (
            trigger  # Field to store the trigger code fragment or artifact
        )

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
            return "No issues found"
        else:
            return self.message


class Analysis(ABC):
    ALL: "List[Analysis]" = []

    def __init_subclass__(cls, **kwargs):
        Analysis.ALL.append(cls())

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        raise NotImplementedError()


class DuplicateProtoAnalysis(Analysis):
    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        had_proto = False
        proto_versions: Set[int] = set()
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

class NonStandardImportsML(Analysis):
    CALLABLE_NEW_SAFE_MSG = "This class is callable but the call redirects to __new__ which just builds a new object."
    BW_HOOKS_SAFE_MSG = "The `backward_hooks` argument can seem unsafe but can be exploited only if the "
    "pickle can generate malicious callable objects. Since generating a malicious callable is sufficient for "
    "the attacker to execute arbitrary code, using `backward_hooks` is not needed. So this function can be "
    "considered safe."
    ENUM_MSG = "A simple enumeration."
    DATACLASS_MSG = "A simple dataclass that can update itself from a dict, and load/save from a JSON file."
    SIMPLE_CLASS_MSG = "A simple class that is not callable and can not be used as a code exec or `getattr` primitive. "
                       "The class doesn't have security-sensitive parameters or attributes."
    SIMPLE_FUNCTION_MSG = "A simple function that is not callable and can not be used as a code exec or `getattr` primitive."
    BINDING_CLASS_MSG = "A binding class."

    def __init__(self):
        super().__init__()
        # TODO(boyan): actually make sure these whitelisted modules are safe
        self.whitelist = {
            "numpy": {
                "dtype": "A static object that isn't callable.",
                "ndarray": "A static object that isn't callable."
            },
            "numpy.core.multiarray": {
                "_reconstruct": "Helper function that reconstructs a `ndarray` object. Calls the C-code `PyArray_NewFromDescr` constructor under the hood."
            },
            "torch": {
                "ByteStorage": self.CALLABLE_NEW_SAFE_MSG,
                "DoubleStorage": self.CALLABLE_NEW_SAFE_MSG,
                "FloatStorage": self.CALLABLE_NEW_SAFE_MSG,
                "HalfStorage": self.CALLABLE_NEW_SAFE_MSG,
                "LongStorage": self.CALLABLE_NEW_SAFE_MSG,
                "IntStorage": self.CALLABLE_NEW_SAFE_MSG,
                "ShortStorage": self.CALLABLE_NEW_SAFE_MSG,
                "CharStorage": self.CALLABLE_NEW_SAFE_MSG,
                "BoolStorage": self.CALLABLE_NEW_SAFE_MSG,
                "BFloat16Storage": self.CALLABLE_NEW_SAFE_MSG,
                "ComplexDoubleStorage": self.CALLABLE_NEW_SAFE_MSG,
                "ComplexFloatStorage": self.CALLABLE_NEW_SAFE_MSG,
                "QUInt8Storage": self.CALLABLE_NEW_SAFE_MSG,
                "QInt8Storage": self.CALLABLE_NEW_SAFE_MSG,
                "QInt32Storage": self.CALLABLE_NEW_SAFE_MSG,
                "QUInt4x2Storage": self.CALLABLE_NEW_SAFE_MSG,
                "QUInt2x4Storage": self.CALLABLE_NEW_SAFE_MSG,
                "Size": self.CALLABLE_NEW_SAFE_MSG,
                "device": self.CALLABLE_NEW_SAFE_MSG,
                "Tensor": self.CALLABLE_NEW_SAFE_MSG,
                "bfloat16": self.SIMPLE_CLASS_MSG,
                "float16": self.SIMPLE_CLASS_MSG,
            },
            "torch._tensor": {
                "_rebuild_from_type_v2": f"This function accepts another function as argument and calls it on the rest of the arguments. "
                                          "The returned type is expected to be a `torch.Tensor` but could be something else. `__setstate__` is finally called on the "
                                          "returned object using the last argument. This function thus doesn't do anything that couldn't b already achieved using the "
                                          "REDUCE and BUILD opcodes directly.",
            },
            "torch._utils": {
                "_rebuild_tensor": f"Builds a `torch.Tensor` object. {self.CALLABLE_NEW_SAFE_MSG}",
                "_rebuild_tensor_v2": f"Builds a `torch.Tensor` object. {self.CALLABLE_NEW_SAFE_MSG} {self.BW_HOOKS_SAFE_MSG}",   
                "_rebuild_parameter": f"Builds a `torch.Parameter` object. {self.CALLABLE_NEW_SAFE_MSG} {self.BW_HOOKS_SAFE_MSG}"
            },
            "transformers.training_args": {
                "TrainingArguments": "TODO: maybe not safe? See push to hub",
                "OptimizerNames": self.ENUM_MSG,
                "CustomTrainingArguments": "TODO",
            },
            "transformers.training_args_seq2seq": {
                "Seq2SeqTrainingArguments": "TODO, a subclass of transformers.TrainingArgs",
            },
            "transformers.deepspeed": {
                "HfTrainerDeepSpeedConfig": "Imported from `transformers.integrations.deepspeed`",
                "HfDeepSpeedConfig": "Imported from `transformers.integrations.deepspeed`",
            },
            "transformers.integrations.deepspeed": {
                "HfTrainerDeepSpeedConfig": "A subclass of the safe `accelerate.utils.deepspeed.HfDeepSpeedConfig`, with more fields.",
                "HfDeepSpeedConfig": "A renamed import of the safe `accelerate.utils.deepspeed.HfDeepSpeedConfig` or python `object`.",    
            },
            "transformers.trainer_pt_utils": {
                "AcceleratorConfig": self.DATACLASS_MSG,
            },
            "transformers.trainer_utils": {
                "IntervalStrategy": self.ENUM_MSG,
                "SchedulerType": self.ENUM_MSG,
                "HubStrategy": self.ENUM_MSG,
                "EvaluationStrategy": self.ENUM_MSG,
            },
            "simpletransformers.config.model_args": {
                "Seq2SeqArgs": self.DATACLASS_MSG,
                "NERArgs": self.DATACLASS_MSG,
                "ClassificationArgs": self.DATACLASS_MSG,
                "QuestionAnsweringArgs": self.DATACLASS_MSG,
                "T5Args": self.DATACLASS_MSG,
                "GenerationArgs": self.DATACLASS_MSG,
                "LanguageModelingArgs": self.DATACLASS_MSG,
                "RetrievalArgs": self.DATACLASS_MSG,
                "MultiLabelClassificationArgs": self.DATACLASS_MSG,
            },
            "accelerate.state": {
                "PartialState": "A complex class that can not be used as a dangerous primitive. It's initialisation code "
                                "accepts the init_method kwarg for distributed training, but it can't be exploited as it needs "
                                f"to point to a node that has been initialised by the user. {self.CALLABLE_NEW_SAFE_MSG}"
            },
            "accelerate.utils.deepspeed": {
                "HfDeepSpeedConfig": "A wrapper class for a nested dictionnary. The class could be used to call a `get()` method through `get_value()` on an arbitrary object passed to the constructor. "
                                     "However, the class constructor enforces a type check of the object and forces it to be a dict or a filepath. So this can't be exploited in practice to become a "
                                     "`getattr` or similar primitive.",
            },
            "accelerate.utils.dataclasses": {
                "DistributedType": self.ENUM_MSG,
                "DeepSpeedPlugin": self.ENUM_MSG,
            },
            "torch.nn.modules.linear": {
                "Linear": self.SIMPLE_CLASS_MSG,
            },
            "torch.storage": {
                "_load_from_bytes": "TODO: This function calls `torch.load()` which is unsafe as using a string argument would "
                                    "allow to load and execute arbitrary code hosted on the internet. However, in this case, the "
                                    "argument is explicitly converted to `io.bytesIO` and hence treated as a bytestream and not as "
                                    "a remote URL. Note that supplying a pickle opcode bytestring as argument to this function also causes the "
                                    "underlying `torch.load()` call to unpickle that bytestring, so this is safe only if restrictions on pickle "
                                    "(such as Fickling's hooks) have been set properly.",
            },
            "_io": {"BytesIO": self.SIMPLE_CLASS_MSG},
            "_codecs": {"encode": self.SIMPLE_FUNCTION_MSG},
            "collections": {
                "OrderedDict": self.SIMPLE_CLASS_MSG,
                "defaultdict": self.SIMPLE_CLASS_MSG,
            },
            "argparse": {
                "Namespace": self.SIMPLE_CLASS_MSG,
            },
            "llava.train.train": {
                "TrainingArguments": "TODO. Subclass of Tranformers.TrainingArguments",
            },
            "tokenizers": {
                "Tokenizer": "A binding for the class implemented in Rust at https://github.com/huggingface/tokenizers/blob/main/bindings/python/src/tokenizer.rs. "
                             "While the `Tokenizer.from_pretrained()` is dangerous and could lead to arbitrary code execution, it can not be reached as the Rust constructor "
                             "only accepts one positional argument, and no keyword arguments such as `name_or_path`.",
                "AddedToken": self.BINDING_CLASS_MSG,
            },
            "tokenizers.models": {
                "Model": f"{self.BINDING_CLASS_MSG} This class can not be constructed directly from Python.",
            },
            "transformers.models.bert.tokenization_bert_fast": {
                "BertTokenizerFast": "This class only loads a local tokenizer. The keyword argument `name_or_path` is ignored and thus can not be used to load a third "
                                     "party Tokenizer from the hub, which would lead to code execution",
            },
            "trl.trainer.sft_config": {
                "SFTConfig": "TODO. Subclass of transformers.TrainingArguments",
            },
            "FlagEmbedding.baai_general_embedding.finetune.arguments": {
                "RetrieverTrainingArguments": "TODO. Just tranformers.TrainingArguments",
            },
            "h4.training.configs.sft_config": {
                "SFTConfig": "TODO: where is this lib???",
            },
            "h4.training.config": {
                "DPOTrainingArguments": "TODO",
                "TrainingArguments": "TODO",
            },
            "alignment.configs": {
                "SFTConfig": "TODO Same as `trl.SFTConfig` which is a derives from transformers.TrainingArgs",
            },
        }

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.imports:
            shortened, already_reported = context.shorten_code(node)
            if not already_reported:
                if node.module not in self.whitelist:
                    yield AnalysisResult(
                        Severity.LIKELY_UNSAFE,
                        f"`{shortened}` imports a Python module outside of "
                        "the standard library that is not whitelisted; "
                        "this could execute arbitrary code and is "
                        "inherently unsafe",
                        "NonStandardImportsML",
                        trigger=shortened,
                    )
                else:
                    for n in node.names:
                        if n.name not in self.whitelist[node.module]:
                            yield AnalysisResult(
                                Severity.LIKELY_UNSAFE,
                                f"`{shortened}` imports the non-standard Python function `{n.name}` that is not whitelisted as safe; "
                                "this could execute arbitrary code and is "
                                "inherently unsafe",
                                "NonStandardImportsML",
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
        "torch": {"load":"This function can load untrusted files and code from arbitrary web sources."},
        "numpy.testing._private.utils": {"runstring": "This function can execute arbitrary code."},
        "operator": {
            "getitem": "This function can lead to arbitrary code execution",
            "attrgetter": "This function can lead to arbitrary code execution",
            "itemgetter": "This function can lead to arbitrary code execution",
            "methodcaller": "This function can lead to arbitrary code execution",
        },
    }

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.imports:
            shortened, _ = context.shorten_code(node)
            all_modules = [node.module.rsplit(".", i)[0] for i in range(0, node.module.count(".")+1)]
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
                    f"Call to `{shortened}` is almost certainly evidence of a "
                    "malicious pickle file",
                    "OvertlyBadEval",
                    trigger=shortened,
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
                or shortened.startswith("_run_code(")
                or shortened.startswith("execWrapper(")
            ):
                # this is overtly bad, so record it and print it at the end
                yield AnalysisResult(
                    Severity.OVERTLY_MALICIOUS,
                    f"Call to `{shortened}` is almost certainly evidence of a "
                    "malicious pickle file",
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
        self.results: Tuple[AnalysisResult, ...] = tuple(results)

    @property
    def severity(self) -> Severity:
        if not self.results:
            return Severity.LIKELY_SAFE
        return max(r.severity for r in self.results)

    def __bool__(self):
        """Returns True if all analyses failed to find any unsafe operations"""
        return all(map(bool, sorted(self.results)))

    def detailed_results(self) -> Dict[str, Dict[str, str]]:
        detailed = defaultdict(dict)
        for result in self.results:
            if result.trigger:
                detailed["AnalysisResult"][result.analysis_name] = result.trigger
        return dict(detailed)

    def to_string(self, verbosity: Severity = Severity.SUSPICIOUS):
        return "\n".join(str(r) for r in self.results if verbosity <= r.severity)

    __str__ = to_string

    def to_dict(self, verbosity: Severity = Severity.SUSPICIOUS):
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
    analyzer: Optional[Analyzer] = None,
    verbosity: Severity = Severity.SUSPICIOUS,
    json_output_path: Optional[str] = None,
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
