import importlib.abc
import importlib.machinery
import sys
from types import ModuleType
from typing import Sequence, Union
import types
import fickling.fickle as fickle
import pickle as original_pickle
import fickling.hook as hook


class FickleLoader(importlib.abc.Loader):
    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType:
        return None
    
    def exec_module(self, module: types.ModuleType) -> None:
        module.load = hook.wrapped_load 
        

class PickleFinder(importlib.abc.MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Sequence[Union[bytes, str]] | None,
        target: ModuleType | None = None,
    ):
        if fullname == 'pickle':
            print("Pickle module found: Running import hook")
            return importlib.machinery.ModuleSpec(fullname, FickleLoader())
        return None


def run_import_hook():
    if 'pickle' in sys.modules:
        del sys.modules['pickle']
    sys.meta_path.insert(0, PickleFinder())


""" #Uncomment the following lines to test the code
if __name__ == "__main__":
    from fickling.import_hook import run_hook

    run_import_hook()

    import pickle

    with open("test.pkl", "rb") as file:
        loaded_data = pickle.load(file)
        print("Loaded data:", loaded_data)
"""