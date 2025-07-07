import pickle
from collections.abc import Iterator

from fickling.analysis import Analysis, AnalysisContext, AnalysisResult, Severity
from fickling.exception import UnsafeFileError

CALLABLE_NEW_SAFE_MSG = "This class is callable but the call redirects to __new__ which just builds a new object."
BW_HOOKS_SAFE_MSG = (
    "The `backward_hooks` argument can seem unsafe but can be exploited only if the "
    "pickle can generate malicious callable objects. Since generating a malicious callable is sufficient for "
    "the attacker to execute arbitrary code, using `backward_hooks` is not needed. So this function can be "
    "considered safe."
)

ENUM_MSG = "A simple enumeration."
DATACLASS_MSG = "A simple dataclass that can update itself from a dict, and load/save from a JSON file."
SIMPLE_CLASS_MSG = "A simple class that is not callable and can not be used as a code exec or `getattr` primitive. "
"The class doesn't have security-sensitive parameters or attributes."
SIMPLE_FUNCTION_MSG = "A simple function that is not callable and can not be used as a code exec or `getattr` primitive."
BINDING_CLASS_MSG = "A binding class."

TRANSFORMERS_TRAININGARGS_MSG = (
    "A dataclass for model training parameters."
    "The `push_to_hub` field can lead to model uploads to public repositories and should "
    "be used with caution. Other than that no fields can not be used for arbitrary code execution."
)

TRAININGARGS_SUBCLASS_MSG = "A subclass deriving from transformers.training_args.TrainingArguments."
MAIN_IMPORT_MSG = (
    "We consider this name safe to import from __main__ because it doesn't overlap " "with names of known pickle exploit primitives. "
)

# Allowlist for imports that can be considered safe when scanning a file
# without actually loading it. This typically excludes imports that could
# lead to pickle-inside-pickle calls because scanning-only scan not analyze
# nested pickle payloads
ML_ALLOWLIST = {
    "numpy": {
        "dtype": "A static object that isn't callable.",
        "ndarray": "A static object that isn't callable.",
        "float64": BINDING_CLASS_MSG,
    },
    "numpy.core.multiarray": {
        "_reconstruct": "Helper function that reconstructs a `ndarray` object. Calls the C-code "
        "`PyArray_NewFromDescr` constructor under the hood."
    },
    "numpy._core.multiarray": {
        "_reconstruct": "Helper function that reconstructs a `ndarray` object. Calls the C-code "
        "`PyArray_NewFromDescr` constructor under the hood."
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
        "float32": SIMPLE_CLASS_MSG,
    },
    "torch._tensor": {
        "_rebuild_from_type_v2": "This function accepts another function as argument and calls it on the rest of the arguments. "
        "The returned type is expected to be a `torch.Tensor` but could be something else. `__setstate__` is finally called on the "
        "returned object using the last argument. This function thus doesn't do anything that couldn't be already achieved using the "
        "REDUCE and BUILD opcodes directly.",
    },
    "torch.storage": {
        "_load_from_bytes": "First, this function calls `torch.load()` which is unsafe as using a string argument would "
        "allow to load and execute arbitrary code hosted on the internet. However, in this case, the "
        "argument is explicitly converted to `io.bytesIO` and hence treated as a bytestream and not as "
        "a remote URL. Second, a malicious file can supply a pickle opcode bytestring as argument to this function to cause the "
        "underlying `torch.load()` call to unpickle that bytestring and execute arbitrary code through nested pickle calls. "
        "However, this import can be considered safe when used with the Fickling unpickler because it also catches nested pickle-inside-pickle payloads.",
    },
    "torch._utils": {
        "_rebuild_tensor": f"Builds a `torch.Tensor` object. {CALLABLE_NEW_SAFE_MSG}",
        "_rebuild_tensor_v2": f"Builds a `torch.Tensor` object. {CALLABLE_NEW_SAFE_MSG} {BW_HOOKS_SAFE_MSG}",
        "_rebuild_parameter": f"Builds a `torch.Parameter` object. {CALLABLE_NEW_SAFE_MSG} {BW_HOOKS_SAFE_MSG}",
    },
    "transformers.training_args": {
        "TrainingArguments": TRANSFORMERS_TRAININGARGS_MSG,
        "OptimizerNames": ENUM_MSG,
    },
    "transformers.training_args_seq2seq": {
        "Seq2SeqTrainingArguments": TRAININGARGS_SUBCLASS_MSG,
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
        "FSDPOption": ENUM_MSG,
        "SaveStrategy": ENUM_MSG,
        "ShardedDDPOption": ENUM_MSG,
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
        "Identity": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.upsampling": {
        "Upsample": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.pooling": {
        "MaxPool2d": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.batchnorm": {
        "BatchNorm2d": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.conv": {
        "Conv2d": SIMPLE_CLASS_MSG,
        "ConvTranspose2d": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.activation": {
        "SiLU": SIMPLE_CLASS_MSG,
    },
    "torch.nn.modules.loss": {
        "BCEWithLogitsLoss": SIMPLE_CLASS_MSG,
    },
    "ultralytics.nn.modules.block": {
        "SPPF": SIMPLE_CLASS_MSG,
        "DFL": SIMPLE_CLASS_MSG,
        "Bottleneck": SIMPLE_CLASS_MSG,
        "C2f": SIMPLE_CLASS_MSG,
        "Proto": SIMPLE_CLASS_MSG,
        "PSABlock": SIMPLE_CLASS_MSG,
        "C3k2": SIMPLE_CLASS_MSG,
        "C3k": SIMPLE_CLASS_MSG,
        "C2PSA": SIMPLE_CLASS_MSG,
        "Attention": SIMPLE_CLASS_MSG,
    },
    "ultralytics.nn.modules.head": {
        "Detect": SIMPLE_CLASS_MSG,
        "Segment": SIMPLE_CLASS_MSG,
    },
    "ultralytics.nn.modules.batchnorm": {
        "BatchNorm2d": SIMPLE_CLASS_MSG,
    },
    "ultralytics.nn.modules.conv": {
        "Concat": SIMPLE_CLASS_MSG,
        "Conv": SIMPLE_CLASS_MSG,
        "DWConv": SIMPLE_CLASS_MSG,
    },
    "ultralytics.utils.loss": {
        "BboxLoss": SIMPLE_CLASS_MSG,
        "v8SegmentationLoss": SIMPLE_CLASS_MSG,
    },
    "ultralytics.utils.tal": {
        "TaskAlignedAssigner": SIMPLE_CLASS_MSG,
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
        "TrainingArguments": TRAININGARGS_SUBCLASS_MSG,
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
        "SFTConfig": TRAININGARGS_SUBCLASS_MSG,
    },
    "FlagEmbedding.baai_general_embedding.finetune.arguments": {
        "RetrieverTrainingArguments": TRAININGARGS_SUBCLASS_MSG,
    },
    "h4.training.config": {
        "DPOTrainingArguments": TRAININGARGS_SUBCLASS_MSG,
        "TrainingArguments": TRAININGARGS_SUBCLASS_MSG,
    },
    "alignment.configs": {
        "SFTConfig": f"Same as `trl.SFTConfig`. {TRAININGARGS_SUBCLASS_MSG}",
        "DPOConfig": f"Same as `trl.DPOConfig`. {TRAININGARGS_SUBCLASS_MSG}",
    },
    "copyreg": {
        "_reconstructor": "This function is used to rebuild instances of extension types written in C. "
        "Given a class object and instanciation arguments, it creates a new class instance calling `__new__` then `_init_`"
    },
    "__main__": {
        "TrainingArguments": MAIN_IMPORT_MSG,
        "DistillationTrainingArguments": MAIN_IMPORT_MSG,
        "DistillTrainingArguments": MAIN_IMPORT_MSG,
        "SimPOConfig": MAIN_IMPORT_MSG,
        "TrAr": MAIN_IMPORT_MSG,
    },
    "sklearn.preprocessing._label": {
        "LabelEncoder": SIMPLE_CLASS_MSG,
    },
    "fastchat.train.train": {
        "TrainingArguments": TRAININGARGS_SUBCLASS_MSG,
    },
    "llava.train.train_dpo_ori": {
        "TrainingArguments": TRAININGARGS_SUBCLASS_MSG,
    },
    "trl.trainer.dpo_config": {"FDivergenceType": ENUM_MSG},
    "trl.trainer.grpo_config": {"GRPOConfig": TRAININGARGS_SUBCLASS_MSG},
    "trl.trainer.kto_config": {"KTOConfig": TRAININGARGS_SUBCLASS_MSG},
    "trl.trainer.ppov2_config": {"PPOv2Config": TRAININGARGS_SUBCLASS_MSG},
    "swift.trainers.rlhf_arguments": {"DPOConfig": "Alias for trl.DPOConfig" + TRAININGARGS_SUBCLASS_MSG},
    "open_r1.configs": {
        "SFTConfig": TRANSFORMERS_TRAININGARGS_MSG,
        "GRPOConfig": TRANSFORMERS_TRAININGARGS_MSG,
    },
    "sentence_transformers.training_args": {
        "BatchSamplers": ENUM_MSG,
        "MultiDatasetBatchSamplers": ENUM_MSG,
        "SentenceTransformerTrainingArguments": TRANSFORMERS_TRAININGARGS_MSG,
    },
    "axolotl.core.trainer_builder": {"AxolotlTrainingArguments": TRANSFORMERS_TRAININGARGS_MSG},
    "pyannote.audio.core.task": {
        "Specifications": SIMPLE_CLASS_MSG,
        "Problem": ENUM_MSG,
        "Resolution": ENUM_MSG,
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
                                f"`{shortened}` imports the non-standard `{n.name}` that is not whitelisted as safe; "
                                "this could execute arbitrary code and is "
                                "inherently unsafe",
                                "MLAllowlist",
                                trigger=shortened,
                            )


class FicklingMLUnpickler(pickle.Unpickler):
    def __init__(self, *args, also_allow: list[str] = None, **kwargs):
        self.allowlist = dict(ML_ALLOWLIST)
        super().__init__(*args, **kwargs)
        # Add additional allowed imports
        if also_allow:
            for allowed_import in also_allow:
                module, name = allowed_import.rsplit(".", 1)
                if module in self.allowlist:
                    self.allowlist[module][name] = "Import explicitly allowed by user"
                else:
                    self.allowlist[module] = {name: "Import explicitly allowed by user"}

    def find_class(self, module, name):
        # Check whether import is allowed
        import_str = f"{module}.{name}"
        if module not in self.allowlist:
            raise UnsafeFileError(
                "<file>",
                f"`{import_str}` imports a Python module outside of "
                "the standard library that is not whitelisted; "
                "this could execute arbitrary code and should be considered unsafe",
            )
        elif name not in self.allowlist[module]:
            raise UnsafeFileError(
                "<file>",
                f"`{import_str}` imports the non-standard Python function `{name}` that is not whitelisted as safe; "
                "this could execute arbitrary code and should be considered unsafe",
            )
        return super().find_class(module, name)
