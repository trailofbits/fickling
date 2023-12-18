import importlib.abc
import importlib.machinery
import sys
import types
from types import ModuleType
from typing import Sequence, Union

import fickling.hook as hook
import fickling.loader as loader

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
        # TODO Determine whether I should expose extra loader args


class PickleFinder(importlib.abc.MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Sequence[Union[bytes, str]] | None,
        target: ModuleType | None = None,
    ):
        if fullname == "pickle":
            print("Pickle module found: Running import hook")
            return importlib.machinery.ModuleSpec(fullname, FickleLoader())
        return None


def run_import_hook():
    if "pickle" in sys.modules:
        del sys.modules["pickle"]
    sys.meta_path.insert(0, PickleFinder())
