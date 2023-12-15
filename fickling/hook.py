import pickle
import torch
from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper

def core_load(file, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
    if pytorch==True:
        wrapped = PyTorchModelWrapper(file)
        print(wrapped.formats)
        #if wrapped.pickled:
        pickled_data = wrapped.pickled
        #else:
        #    return False
    else:
        pickled_data = Pickled.load(file)
    result = pickled_data.check_safety.severity
    if result not in block:
        # Apply a fallback in case of custom unpicklers unknown to the user
        if run_after_analysis is True:
            try:
                if pytorch==True:
                    return torch.load(file)
                else:
                    return pickle.loads(pickled_data.dumps())
            except Exception: # noqa
                raise ValueError(
                    """The data could not be dumped and pickled.
                                 Try `run_after_analysis=False` and run
                                 the custom unpickling after."""
                )
        else:
            return True
    else:
        return False


def hook_load(load_function, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
    def wrapper(*args, **kwargs):
        file = args[0]
        return core_load(file, pytorch=pytorch, run_after_analysis=run_after_analysis, block=block)

    return wrapper


def run_hook(run_after_analysis=True, block=[3, 4, 5]):
    pickle.load = hook_load(pickle.load, pytorch=False, run_after_analysis=run_after_analysis, block=block)
    torch.load = hook_load(torch.load, pytorch=True, run_after_analysis=run_after_analysis, block=block)

# pytorch=False, run_after_analysis=True, block=[3, 4, 5]

"""
import pickle

from fickling.fickle import Pickled


def core_load(file, run_after_analysis=True, block=[3, 4, 5]):
    print("Inside core_load")
    pickled_data = Pickled.load(file)
    result = pickled_data.check_safety.severity
    if result not in block:
        # Apply a fallback in case of custom unpicklers unknown to the user
        if run_after_analysis is True:
            try:
                return pickle.loads(pickled_data.dumps())
            except Exception: # noqa
                raise ValueError(
                    """"""
                )
        else:
            return True
    else:
        return False


def hook_pickle_load(pickle_load_function):
    def wrapper(*args, **kwargs):
        file = args[0]
        return core_load(file)

    return wrapper


def run_hook():
    pickle.load = hook_pickle_load(pickle.load)


"""