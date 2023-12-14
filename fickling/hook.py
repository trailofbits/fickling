import importlib.abc
import importlib.machinery
import sys
from types import ModuleType
from typing import Sequence, Union
import types
import fickling.fickle as fickle
#import builtins
#import fickling.fickle as fickle
#original_pickle = builtins.__import__('pickle')
#import pickle as original_pickle

class FickleLoader(importlib.abc.Loader):
    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType:
        #import fickling.fickle as fickle
        return None
    
    def exec_module(self, module: types.ModuleType) -> None:
        #module.__dict__.update(original_pickle.__dict__)

        def custom_load(file, *args, **kwargs):
            print("Using custom load")
            pickled_data = fickle.Pickled.load(file)
            if pickled_data.is_likely_safe is True:
                print("Safe")
                return True
                #return original_pickle.loads(pickled_data.dumps(), *args, **kwargs)
            else:
                return False

        module.load = custom_load #fickle.Pickled.load
        print("Custom load function set:", "load" in module.__dict__)
        

class PickleFinder(importlib.abc.MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Sequence[Union[bytes, str]] | None,
        target: ModuleType | None = None,
    ):
        if fullname == 'pickle':
            print("Replacing pickle module")
            return importlib.machinery.ModuleSpec(fullname, FickleLoader())
        return None


def run_hook():
    import sys
    if 'pickle' in sys.modules:
        del sys.modules['pickle']
    sys.meta_path.insert(0, PickleFinder())

"""
if __name__ == "__main__":
    sys.meta_path.insert(0, PickleFinder())

    if 'pickle' in sys.modules:
        del sys.modules['pickle']
        #pass
    import pickle
    
    with open("test.pkl", "rb") as file:
        loaded_data = pickle.load(file)
        print("Loaded data:", loaded_data)
"""
