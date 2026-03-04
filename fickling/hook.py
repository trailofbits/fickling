import _pickle
import io
import pickle

import fickling.loader as loader
from fickling.analysis import Severity
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


def run_hook(max_acceptable_severity=Severity.LIKELY_SAFE):
    """Replace pickle.load() and pickle.Unpickler by fickling's safe versions

    Args:
        max_acceptable_severity: Maximum severity level to allow through.
            When non-default, wraps loader functions to pass the threshold.
    """
    if max_acceptable_severity != Severity.LIKELY_SAFE:

        def hooked_load(file, *args, **kwargs):
            kwargs.pop("max_acceptable_severity", None)
            return loader.load(
                file, *args, max_acceptable_severity=max_acceptable_severity, **kwargs
            )

        def hooked_loads(data, *args, **kwargs):
            kwargs.pop("max_acceptable_severity", None)
            return loader.loads(
                data, *args, max_acceptable_severity=max_acceptable_severity, **kwargs
            )

        pickle.load = hooked_load
        _pickle.load = hooked_load
        pickle.loads = hooked_loads
        _pickle.loads = hooked_loads

        # Create Unpickler subclass that passes severity through
        class SafetyUnpicklerWithSeverity(FicklingSafetyUnpickler):
            def __init__(self, file, *args, **kwargs):
                kwargs.pop("max_acceptable_severity", None)
                super().__init__(file, *args, **kwargs)

            def load(self):
                return loader.load(
                    self._file,
                    *self._args,
                    max_acceptable_severity=max_acceptable_severity,
                    **self._kwargs,
                )

        pickle.Unpickler = SafetyUnpicklerWithSeverity
        _pickle.Unpickler = SafetyUnpicklerWithSeverity
    else:
        pickle.load = loader.load
        _pickle.load = loader.load
        pickle.loads = loader.loads
        _pickle.loads = loader.loads
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


def snapshot_hooks():
    """Capture the current state of all hooked pickle entry points."""
    return (
        pickle.load,
        _pickle.load,
        pickle.loads,
        _pickle.loads,
        pickle.Unpickler,
        _pickle.Unpickler,
    )


def restore_hooks(snapshot):
    """Restore pickle entry points from a previous snapshot."""
    pickle.load = snapshot[0]
    _pickle.load = snapshot[1]
    pickle.loads = snapshot[2]
    _pickle.loads = snapshot[3]
    pickle.Unpickler = snapshot[4]
    _pickle.Unpickler = snapshot[5]


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
