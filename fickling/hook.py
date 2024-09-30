import pickle

import fickling.loader as loader
from fickling.ml import FicklingMLUnpickler

def run_hook():
    """Replace pickle.load() by fickling's load()"""
    pickle.load = loader.load


def always_check_safety():
    """
    Alias for run_hook()
    """
    run_hook()


def restrict_to_ml_models():
    """Enforce using the ML whitelist unpickler"""
    def new_load(file, *args, **kwargs):
        return FicklingMLUnpickler(file).load(*args, **kwargs)
    pickle.load = new_load