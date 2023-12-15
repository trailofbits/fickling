import pickle
import torch
from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper
import fickling.loader as loader 

def hook_pickle_load(pickle_load_function):
    def wrapper(*args, **kwargs):
        file = args[0]
        return loader.load(file)

    return wrapper


def run_hook():
    pickle.load = hook_pickle_load(pickle.load)


# TODO Determine whether to keep this or not
def core_load_with_torch(file, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
    if pytorch==True:
        wrapped = PyTorchModelWrapper(file)
        pickled_data = wrapped.pickled
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


def hook_load_with_torch(load_function, pytorch=False, run_after_analysis=True, block=[3, 4, 5]):
    def wrapper(*args, **kwargs):
        file = args[0]
        return core_load_with_torch(file, pytorch=pytorch, run_after_analysis=run_after_analysis, block=block)

    return wrapper


def run_hook_with_torch(run_after_analysis=True, block=[3, 4, 5]):
    pickle.load = hook_load_with_torch(pickle.load, pytorch=False, run_after_analysis=run_after_analysis, block=block)
    torch.load = hook_load_with_torch(torch.load, pytorch=True, run_after_analysis=run_after_analysis, block=block)