import importlib.abc
import importlib.machinery
import sys
from types import ModuleType
from typing import Sequence, Union
import types
import fickling.fickle as fickle
import pickle as original_pickle

class FickleLoader(importlib.abc.Loader):
    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType:
        return None
    
    def exec_module(self, module: types.ModuleType) -> None:
        def custom_load(file, *args, **kwargs):
            pickled_data = fickle.Pickled.load(file)
            if pickled_data.is_likely_safe is True:
                return original_pickle.loads(pickled_data.dumps(), *args, **kwargs)
            else:
                return None

        module.load = custom_load 
        

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


def run_hook():
    if 'pickle' in sys.modules:
        del sys.modules['pickle']
    sys.meta_path.insert(0, PickleFinder())


""" Uncomment the following lines to test the code
if __name__ == "__main__":
    from fickling.import_hook import run_hook

    run_hook()

    import pickle

    with open("test.pkl", "rb") as file:
        loaded_data = pickle.load(file)
        print("Loaded data:", loaded_data)
""" 