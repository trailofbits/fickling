import json
import os

# To run model unpickler
import pickle
import pickletools
import random
import sys
import traceback
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional

import logger
import picklescan.scanner as ps_scanner
import torch._C
from model_unpickler import SafeUnpickler
from modelscan.modelscan import ModelScan

from fickling.analysis import Analyzer, BadCalls, Severity, UnsafeImportsML, check_safety
from fickling.fickle import Pickled
from fickling.ml import MLAllowlist
from fickling.pytorch import PyTorchModelWrapper


class ModelUnpickler(SafeUnpickler):
    def persistent_load(self, pid):
        return None


setattr(pickle, "Unpickler", SafeUnpickler)

# Logging
ps_scanner._log.propagate = False
DEVNULL = open(os.devnull, "w")


# TODO(boyan): do this when downloading the files
def is_valid(filepath, filetype):
    if not os.path.isfile(filepath):
        return False
    with open(filepath, "rb") as f:
        if f.read(100).startswith(b"Access to model"):
            # HF access denied...
            return False

    if filetype == "pickle":
        with open(filepath, "rb") as f:
            try:
                pickletools.dis(f, out=DEVNULL)
                return True
            except Exception as e:
                logger.error(f"Invalid pickle file {filepath}: {e}")
                return False
    elif filetype == "pytorch":
        return zipfile.is_zipfile(filepath)
    else:
        raise Exception("Unsupported file type")


def load_index(filepath):
    with open(filepath) as f:
        return json.load(f)


def run_fickling(filepath, filetype):
    analysis = [
        MLAllowlist(),  # Import non standard non whitelisted stuff
        UnsafeImportsML(),  # Importing from unsafe modules
        BadCalls(),  # Overtly bad calls to built-in functions
    ]
    if filetype == "pickle":
        return run_fickling_pickle(filepath, analysis)
    elif filetype == "pytorch":
        return run_fickling_pytorch(filepath, analysis)


def run_fickling_pickle(filepath, analysis) -> bool:
    """Return true if the file is considered safe"""
    with open(filepath, "rb") as f:
        pickled = Pickled.load(f)
        res = check_safety(pickled, analyzer=Analyzer(analysis))
        print(res)
        return res.severity == Severity.LIKELY_SAFE


def run_fickling_pytorch(filepath, analysis) -> bool:
    wrapper = PyTorchModelWrapper(filepath)
    res = check_safety(wrapper.pickled, analyzer=Analyzer(analysis))
    print(res)
    return res.severity == Severity.LIKELY_SAFE


def run_modelscan(filepath, filetype):
    ms = ModelScan()
    res = ms.scan(filepath)
    if res["issues"]:
        return False
    return True


def run_modelunpickler(filepath, filetype):
    # print(filepath)
    try:
        if filetype == "pickle":
            with open(filepath, "rb") as f:
                ModelUnpickler(f).load()
        elif filetype == "pytorch":
            torch.load(filepath, map_location=torch.device("cpu"))
    except (pickle.UnpicklingError, AttributeError) as e:
        print(e)
        return False
    return True


def run_picklescan(filepath, filetype):
    results = ps_scanner.scan_file_path(filepath)
    if results.scan_err:
        raise Exception("Failed to analyze file with picklescan. res.scan_err = True")
    if results.issues_count == 0:
        return True  # Safe
    else:
        return False  # Unsafe


def _analyze_file(
    toolname: str,
    run_tool_func: Callable,
    fileinfo: Dict,
    results: Dict[str, "BenchmarkResults"],
    expected_scan_result: bool,  # True for clean files, False for malicious files
    payload: Optional[str] = None,
):
    logger.info(f"Running {toolname} on {fileinfo['file']}")
    # Run tool
    if expected_scan_result:
        try:
            clean = run_tool_func(fileinfo["file"], fileinfo["type"])
            if clean:
                results.tools[toolname].add_tn()
            else:
                results.tools[toolname].add_fp()
                logger.warning(f"Clean file mislabeled by {toolname}: {fileinfo['file']}")
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            print(traceback.format_exc())
            logger.error(f"Failed to analyze file: {e}")
            results.tools[toolname].nb_failed_files += 1
    else:
        try:
            clean = run_tool_func(fileinfo["file"], fileinfo["type"])
            if clean:
                results.tools[toolname].add_fn(payload=payload)
                logger.warning(f"Malicious file missed by {toolname}: {fileinfo['file']}. Payload was: {payload}")
            else:
                results.tools[toolname].add_tp()
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            print(traceback.format_exc())
            logger.error(f"Failed to analyze file: {e}")
            results.tools[toolname].nb_failed_files += 1


def run_benchmark(
    clean_dataset_dir: Path,
    malicious_dataset_dir: Path,
    tools: dict,
    n=10000,
    clean_to_malicious_ratio=2.0,
):
    # Load file indexes
    clean_index = load_index(clean_dataset_dir / "index.json")
    malicious_index = load_index(malicious_dataset_dir / "index.json")

    # Select files for the benchmark
    # Get ratio
    nb_malicious_files = __builtins__.round(n / (1 + clean_to_malicious_ratio))
    nb_clean_files = n - nb_malicious_files
    # Don't get more files that we actually have in the datasets
    nb_malicious_files = __builtins__.min(nb_malicious_files, len(malicious_index))
    nb_clean_files = __builtins__.min(nb_clean_files, len(clean_index))
    # Randomly select the files sample from the datasets
    malicious_files = random.sample(malicious_index, nb_malicious_files)
    clean_files = random.sample(clean_index, nb_clean_files)

    # Run fickling on the files
    # TODO(boyan): for large datasets, shuffle and alternate between clean and malicious...
    results = BenchmarkResults.new(*list(tools.keys()))
    try:
        for f in clean_files:
            if not is_valid(f["file"], f["type"]):
                results.nb_invalid_files += 1
                continue
            results.nb_clean_files += 1
            # Run fickling
            for toolname, runtool in tools.items():
                _analyze_file(toolname, runtool, f, results, expected_scan_result=True)
        for f in malicious_files:
            if not is_valid(f["file"], f["type"]):
                results.nb_invalid_files += 1
                continue
            results.nb_malicious_files += 1
            for toolname, runtool in tools.items():
                _analyze_file(toolname, runtool, f, results, expected_scan_result=False, payload=f["payload"])
    except KeyboardInterrupt:
        pass

    # Print results
    print(results)


@dataclass
class ToolResults:
    # Overall results
    tn_clean: int = 0  # Clean true negatives (good)
    fp_clean: int = 0  # Clean false positive (bad)
    fn_malicious: int = 0  # Malicious false negative (bad)
    tp_malicious: int = 0  # malicious true positive (good)

    nb_scanned_files: int = 0  # Files scanned without errors
    nb_failed_files: int = 0  # The tool failed to scan the files

    fn_payload_types: Dict[str, int] = field(default_factory=dict)  # <payload type> --> how many

    @property
    def total_files(self) -> int:
        return self.nb_scanned_files + self.nb_failed_files

    def add_tn(self, n=1):
        self.tn_clean += n
        self.nb_scanned_files += n

    def add_fp(self, n=1):
        self.fp_clean += n
        self.nb_scanned_files += n

    def add_fn(self, n=1, payload: Optional[str] = None):
        self.fn_malicious += n
        self.nb_scanned_files += n
        if payload:
            if payload in self.fn_payload_types:
                self.fn_payload_types[payload] += n
            else:
                self.fn_payload_types[payload] = n

    def add_tp(self, n=1):
        self.tp_malicious += n
        self.nb_scanned_files += n

    def sanity_check(self):
        assert self.tn_clean + self.tp_malicious + self.fn_malicious + self.fp_clean == self.nb_scanned_files

    def to_str(self, bench_res: "BenchmarkResults"):
        tn_rate = self.tn_clean / bench_res.nb_clean_files
        tp_rate = self.tp_malicious / bench_res.nb_malicious_files
        scan_rate = self.nb_scanned_files / self.total_files
        res = f"""
    Files successfully analyzed: {scan_rate*100:.1f}%
    Clean files correctly classified: {tn_rate*100:.1f}%
    Malicious files correctly classified: {tp_rate*100:.1f}%
"""
        if self.fn_payload_types:
            res += "    Types of payloads not detected by tool:"
            for t, n in self.fn_payload_types.items():
                res += f"\n        {t}: {n}"

        return res


@dataclass
class BenchmarkResults:
    # Overall files
    nb_clean_files: int = 0  # Total seen clean files
    nb_malicious_files: int = 0  # Total seen malicious files
    nb_invalid_files: int = 0  # Files where even pickletools fail

    tools: Dict[str, ToolResults] = field(default_factory=dict)

    @staticmethod
    def new(*tools):
        res = BenchmarkResults()
        for tool in tools:
            res.tools[tool] = ToolResults()
        return res

    @property
    def total_files(self):
        return self.nb_clean_files + self.nb_malicious_files + self.nb_invalid_files

    def __str__(self):
        res = f"""
### Benchmark results

Dataset:
    Valid clean files: {self.nb_clean_files}
    Valid malicious files: {self.nb_malicious_files}
    Invalid files discarded: {self.nb_invalid_files}
"""
        for tool, tool_res in self.tools.items():
            res += f"""\n{tool} results: {tool_res.to_str(self)}\n"""
        return res


if __name__ == "__main__":
    tools = {
        "Fickling": run_fickling,
        # "Modelscan": run_modelscan,
        # "Picklescan": run_picklescan,
        # "Model Unpickler": run_modelunpickler,
    }
    clean_dataset = Path(sys.argv[1])
    malicious_dataset = Path(sys.argv[2])
    run_benchmark(clean_dataset, malicious_dataset, tools)
