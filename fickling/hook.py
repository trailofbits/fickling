import pickle

import torch

import fickling.loader as loader
from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper
import fickling.polyglot as polyglot

def hook_pickle_load(pickle_load_function):
    def wrapper(*args, **kwargs):
        file = args[0]
        return loader.load(file)

    return wrapper


def run_hook():
    pickle.load = hook_pickle_load(pickle.load)



# TODO Determine whether to keep this or not

"""
This code when used on hook_torch_function.py currently results in the following output:

MODEL
Your file is most likely of this format:  PyTorch v1.3 

Your file is most likely of this format:  PyTorch v1.3 

`from torchvision.models.mobilenetv2 import MobileNetV2` imports a Python module that is not a part of the standard library; this can execute arbitrary code and is inherently unsafe
... [TRUNCATED]
Call to `set([])` can execute arbitrary code and is inherently unsafe
Call to `_rebuild_tensor_v2(...)` can execute arbitrary code and is inherently unsafe
...[TRUNCATED]

LEGACY MODEL
Your file is most likely of this format:  PyTorch v0.1.10 

Traceback (most recent call last):
  File "/Users/suhacker/Development/fickling/example/hook_torch_function.py", line 20, in <module>
    torch.load("legacy_model.pt")
  File "/Users/suhacker/Development/fickling/fickling/hook.py", line 129, in wrapper
    return self.core_load_with_torch(file, pytorch=pytorch, run_after_analysis=run_after_analysis, block=block)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/suhacker/Development/fickling/fickling/hook.py", line 96, in core_load_with_torch
    pickled_data = Pickled.load(file)
                   ^^^^^^^^^^^^^^^^^^
  File "/Users/suhacker/Development/fickling/fickling/fickle.py", line 571, in load
    first_pos = pickled.tell()
                ^^^^^^^^^^^^
AttributeError: 'str' object has no attribute 'tell'

"""

import pickle
import torch

class HookManager:
    def __init__(self):
        self.is_torch_load_hooked = False

    def core_load_with_torch(self, file, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
        if pytorch is True:
            result = polyglot.identify_pytorch_file_format(file)
            #import pdb; pdb.set_trace()
            if result == ['PyTorch v1.3']:
                wrapped = PyTorchModelWrapper(file)
                pickled_data = wrapped.pickled
            elif result == ['PyTorch v0.1.10']:
                pickled_data = Pickled.load(file)
            """
            wrapped = PyTorchModelWrapper(file)
            if wrapped.formats == ["PyTorch v0.1.10"]:
                pickled_data = Pickled.load(file)
            else: 
                pickled_data = wrapped.pickled
            """
        else:
            pickled_data = Pickled.load(file)
        result = pickled_data.check_safety.severity
        if result not in block:
            # Apply a fallback in case of custom unpicklers unknown to the user
            if run_after_analysis is True:
                try:
                    if pytorch is True:
                        return torch.load(file)
                    else:
                        return pickle.loads(pickled_data.dumps())
                except Exception:  # noqa
                    raise ValueError(
                        """The data could not be dumped and pickled.
                                    Try `run_after_analysis=False` and run
                                    the custom unpickling after."""
                    )
            else:
                return True
        else:
            return False

    def hook_load_with_torch(self, load_function, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
        def wrapper(*args, **kwargs):
            file = args[0]
            return self.core_load_with_torch(file, pytorch=pytorch, run_after_analysis=run_after_analysis, block=block)

        if pytorch:
            self.is_torch_load_hooked = True

        return wrapper

    def run_hook_with_torch(self, run_after_analysis=True, block=[3, 4, 5]):
        torch.load = self.hook_load_with_torch(torch.load, pytorch=True, run_after_analysis=run_after_analysis, block=block)

        if not self.is_torch_load_hooked:
            pickle.load = self.hook_load_with_torch(pickle.load, pytorch=False, run_after_analysis=run_after_analysis, block=block)
