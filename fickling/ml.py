from fickling.analysis import Analysis, AnalysisContext, AnalysisResult, Severity
from typing import Iterator

CALLABLE_NEW_SAFE_MSG = "This class is callable but the call redirects to __new__ which just builds a new object."
BW_HOOKS_SAFE_MSG = "The `backward_hooks` argument can seem unsafe but can be exploited only if the "
"pickle can generate malicious callable objects. Since generating a malicious callable is sufficient for "
"the attacker to execute arbitrary code, using `backward_hooks` is not needed. So this function can be "
"considered safe."
ENUM_MSG = "A simple enumeration."
DATACLASS_MSG = "A simple dataclass that can update itself from a dict, and load/save from a JSON file."
SIMPLE_CLASS_MSG =  "A simple class that is not callable and can not be used as a code exec or `getattr` primitive. "
"The class doesn't have security-sensitive parameters or attributes."
SIMPLE_FUNCTION_MSG = "A simple function that is not callable and can not be used as a code exec or `getattr` primitive."
BINDING_CLASS_MSG = "A binding class."

# Allowlist for imports that can be considered safe when scanning a file
# without actually loading it. This typically excludes imports that could
# lead to pickle-inside-pickle calls because scanning-only scan not analyze
# nested pickle payloads   
ML_ALLOWLIST = {
    "numpy": {
        "dtype": "A static object that isn't callable.",
        "ndarray": "A static object that isn't callable."
    },
    "numpy.core.multiarray": {
        "_reconstruct": "Helper function that reconstructs a `ndarray` object. Calls the C-code `PyArray_NewFromDescr` constructor under the hood."
    },
    "torch": {
        "ByteStorage": CALLABLE_NEW_SAFE_MSG,
        "DoubleStorage": CALLABLE_NEW_SAFE_MSG,
        "FloatStorage": CALLABLE_NEW_SAFE_MSG,
        "HalfStorage": CALLABLE_NEW_SAFE_MSG,
        "LongStorage": CALLABLE_NEW_SAFE_MSG,
        "IntStorage": CALLABLE_NEW_SAFE_MSG,
        "ShortStorage": CALLABLE_NEW_SAFE_MSG,
        "CharStorage": CALLABLE_NEW_SAFE_MSG,
        "BoolStorage": CALLABLE_NEW_SAFE_MSG,
        "BFloat16Storage": CALLABLE_NEW_SAFE_MSG,
        "ComplexDoubleStorage": CALLABLE_NEW_SAFE_MSG,
        "ComplexFloatStorage": CALLABLE_NEW_SAFE_MSG,
        "QUInt8Storage": CALLABLE_NEW_SAFE_MSG,
        "QInt8Storage": CALLABLE_NEW_SAFE_MSG,
        "QInt32Storage": CALLABLE_NEW_SAFE_MSG,
        "QUInt4x2Storage": CALLABLE_NEW_SAFE_MSG,
        "QUInt2x4Storage": CALLABLE_NEW_SAFE_MSG,
        "Size": CALLABLE_NEW_SAFE_MSG,
        "device": CALLABLE_NEW_SAFE_MSG,
        "Tensor": CALLABLE_NEW_SAFE_MSG,
        "bfloat16": SIMPLE_CLASS_MSG,
        "float16": SIMPLE_CLASS_MSG,
    },
    "torch._tensor": {
        "_rebuild_from_type_v2": f"This function accepts another function as argument and calls it on the rest of the arguments. "
                                    "The returned type is expected to be a `torch.Tensor` but could be something else. `__setstate__` is finally called on the "
                                    "returned object using the last argument. This function thus doesn't do anything that couldn't b already achieved using the "
                                    "REDUCE and BUILD opcodes directly.",
    },
    "torch._utils": {
        "_rebuild_tensor": f"Builds a `torch.Tensor` object. {CALLABLE_NEW_SAFE_MSG}",
        "_rebuild_tensor_v2": f"Builds a `torch.Tensor` object. {CALLABLE_NEW_SAFE_MSG} {BW_HOOKS_SAFE_MSG}",   
        "_rebuild_parameter": f"Builds a `torch.Parameter` object. {CALLABLE_NEW_SAFE_MSG} {BW_HOOKS_SAFE_MSG}"
    },
    "transformers.training_args": {
        "TrainingArguments": "TODO: maybe not safe? See push to hub",
        "OptimizerNames": ENUM_MSG,
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
        "AcceleratorConfig": DATACLASS_MSG,
    },
    "transformers.trainer_utils": {
        "IntervalStrategy": ENUM_MSG,
        "SchedulerType": ENUM_MSG,
        "HubStrategy": ENUM_MSG,
        "EvaluationStrategy": ENUM_MSG,
    },
    "simpletransformers.config.model_args": {
        "Seq2SeqArgs": DATACLASS_MSG,
        "NERArgs": DATACLASS_MSG,
        "ClassificationArgs": DATACLASS_MSG,
        "QuestionAnsweringArgs": DATACLASS_MSG,
        "T5Args": DATACLASS_MSG,
        "GenerationArgs": DATACLASS_MSG,
        "LanguageModelingArgs": DATACLASS_MSG,
        "RetrievalArgs": DATACLASS_MSG,
        "MultiLabelClassificationArgs": DATACLASS_MSG,
    },
    "accelerate.state": {
        "PartialState": "A complex class that can not be used as a dangerous primitive. It's initialisation code "
                        "accepts the init_method kwarg for distributed training, but it can't be exploited as it needs "
                        f"to point to a node that has been initialised by the user. {CALLABLE_NEW_SAFE_MSG}"
    },
    "accelerate.utils.deepspeed": {
        "HfDeepSpeedConfig": "A wrapper class for a nested dictionnary. The class could be used to call a `get()` method through `get_value()` on an arbitrary object passed to the constructor. "
                                "However, the class constructor enforces a type check of the object and forces it to be a dict or a filepath. So this can't be exploited in practice to become a "
                                "`getattr` or similar primitive.",
    },
    "accelerate.utils.dataclasses": {
        "DistributedType": ENUM_MSG,
        "DeepSpeedPlugin": ENUM_MSG,
    },
    "torch.nn.modules.linear": {
        "Linear": SIMPLE_CLASS_MSG,
    },
    "_io": {"BytesIO": SIMPLE_CLASS_MSG},
    "_codecs": {"encode": SIMPLE_FUNCTION_MSG},
    "collections": {
        "OrderedDict": SIMPLE_CLASS_MSG,
        "defaultdict": SIMPLE_CLASS_MSG,
    },
    "argparse": {
        "Namespace": SIMPLE_CLASS_MSG,
    },
    "llava.train.train": {
        "TrainingArguments": "TODO. Subclass of Tranformers.TrainingArguments",
    },
    "tokenizers": {
        "Tokenizer": "A binding for the class implemented in Rust at https://github.com/huggingface/tokenizers/blob/main/bindings/python/src/tokenizer.rs. "
                        "While the `Tokenizer.from_pretrained()` is dangerous and could lead to arbitrary code execution, it can not be reached as the Rust constructor "
                        "only accepts one positional argument, and no keyword arguments such as `name_or_path`.",
        "AddedToken": BINDING_CLASS_MSG,
    },
    "tokenizers.models": {
        "Model": f"{BINDING_CLASS_MSG} This class can not be constructed directly from Python.",
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

class MLAllowlist(Analysis):
    def __init__(self):
        super().__init__()
        self.allowlist = ML_ALLOWLIST

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisResult]:
        for node in context.pickled.properties.imports:
            shortened, already_reported = context.shorten_code(node)
            if not already_reported:
                if node.module not in self.allowlist:
                    yield AnalysisResult(
                        Severity.LIKELY_UNSAFE,
                        f"`{shortened}` imports a Python module outside of "
                        "the standard library that is not whitelisted; "
                        "this could execute arbitrary code and is "
                        "inherently unsafe",
                        "MLAllowlist",
                        trigger=shortened,
                    )
                else:
                    for n in node.names:
                        if n.name not in self.allowlist[node.module]:
                            yield AnalysisResult(
                                Severity.LIKELY_UNSAFE,
                                f"`{shortened}` imports the non-standard Python function `{n.name}` that is not whitelisted as safe; "
                                "this could execute arbitrary code and is "
                                "inherently unsafe",
                                "MLAllowlist",
                                trigger=shortened,
                            )