import pickle
import _pickle

import io
import fickling.loader as loader
from fickling.ml import FicklingMLUnpickler

_original_pickle_load = pickle.load
_original_pickle_loads = pickle.loads

def run_hook():
    """Replace pickle.load() by fickling's load()"""
    pickle.load = loader.load

def always_check_safety():
    """
    Alias for run_hook()
    """
    run_hook()

def restrict_to_ml_models(also_allow=None):
    """Enforce using the ML whitelist unpickler"""
    def new_load(file, *args, **kwargs):
        return FicklingMLUnpickler(file, also_allow=also_allow).load(*args, **kwargs)

    def new_loads(data, *args, **kwargs):
        return FicklingMLUnpickler(io.BytesIO(data), also_allow=also_allow).load(*args, **kwargs)

    pickle.load = new_load
    _pickle.load = new_load
    pickle.loads = new_loads
    _pickle.loads = new_loads

def remove_hook():
    pickle.load = _original_pickle_load
    _pickle.load = _original_pickle_load
    pickle.loads = _original_pickle_loads
    _pickle.loads = _original_pickle_loads