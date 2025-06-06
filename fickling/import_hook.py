import importlib.abc
import importlib.machinery
import sys
import types
import warnings
from collections.abc import Sequence
from types import ModuleType
from typing import Union

import fickling.loader as loader

warnings.warn(
    "This feature is experimental and should not be used for safety-critical endeavors.",
    category=UserWarning,
    stacklevel=2,
)

"""
This is a Python import hook that will halt pickling if a file is high severity.
This MUST be run BEFORE importing pickle.

Example Code:
```
run_import_hook()

import pickle

with open("example_pickle_file.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)
```
"""


class FickleLoader(importlib.abc.Loader):
    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType:
        return None

    def exec_module(self, module: types.ModuleType) -> None:
        module.load = loader.load


class PickleFinder(importlib.abc.MetaPathFinder):
    def __init__(self, verbose=False):
        self.verbose = verbose

    def find_spec(
        self,
        fullname: str,
        path: Sequence[Union[bytes, str]] | None,
        target: ModuleType | None = None,
    ):
        if fullname == "pickle":
            if self.verbose:
                print("Pickle module found: Running import hook")
            return importlib.machinery.ModuleSpec(fullname, FickleLoader())
        return None


def run_import_hook(verbose=False):
    if "pickle" in sys.modules:
        del sys.modules["pickle"]
    sys.meta_path.insert(0, PickleFinder(verbose=verbose))
