import _pickle
import io
import pickle

import fickling.loader as loader
from fickling.ml import FicklingMLUnpickler

_original_pickle_load = pickle.load
_original_pickle_loads = pickle.loads
_original_pickle_Unpickler = pickle.Unpickler
_original__pickle_Unpickler = _pickle.Unpickler


class FicklingSafetyUnpickler:
    """
    Drop-in replacement for pickle.Unpickler that uses fickling's safety analysis.

    This class intercepts direct uses of pickle.Unpickler() (e.g., by PyTorch v1.3+)
    and routes them through fickling's load() function for security analysis.
    """

    def __init__(self, file, *args, **kwargs):
        self._file = file
        self._args = args
        self._kwargs = kwargs

    def load(self):
        """Delegate to fickling.load() for security analysis"""
        return loader.load(self._file, *self._args, **self._kwargs)


def run_hook():
    """Replace pickle.load() and pickle.Unpickler by fickling's safe versions"""
    # Hook the function
    pickle.load = loader.load

    # Hook the Unpickler class
    pickle.Unpickler = FicklingSafetyUnpickler
    _pickle.Unpickler = FicklingSafetyUnpickler


def always_check_safety():
    """
    Alias for run_hook()
    """
    run_hook()


def activate_safe_ml_environment(also_allow=None):
    """Enforce using the ML whitelist unpickler"""

    def new_load(file, *args, **kwargs):
        return FicklingMLUnpickler(file, also_allow=also_allow, **kwargs).load(*args)

    def new_loads(data, *args, **kwargs):
        return FicklingMLUnpickler(io.BytesIO(data), also_allow=also_allow, **kwargs).load(*args)

    # Hook functions
    pickle.load = new_load
    _pickle.load = new_load
    pickle.loads = new_loads
    _pickle.loads = new_loads

    # Hook Unpickler class - create a subclass that passes also_allow
    class SafeMLUnpickler(FicklingMLUnpickler):
        """Unpickler with pre-configured also_allow list"""

        def __init__(self, file, *args, **kwargs):
            super().__init__(file, *args, also_allow=also_allow, **kwargs)

    pickle.Unpickler = SafeMLUnpickler
    _pickle.Unpickler = SafeMLUnpickler


def remove_hook():
    """Restore original pickle functions and classes"""
    pickle.load = _original_pickle_load
    _pickle.load = _original_pickle_load
    pickle.loads = _original_pickle_loads
    _pickle.loads = _original_pickle_loads
    pickle.Unpickler = _original_pickle_Unpickler
    _pickle.Unpickler = _original__pickle_Unpickler


# Alias
deactivate_safe_ml_environment = remove_hook
