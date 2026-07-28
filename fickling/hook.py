import _pickle
import io
import pickle

from fickling import loader
from fickling.ml import FicklingMLUnpickler

# pickle._* are the Python implementations, and are still usable even
# when the C accelerator is loaded.
_LOAD_TARGETS = ((pickle, "load"), (pickle, "_load"), (_pickle, "load"))
_LOADS_TARGETS = ((pickle, "loads"), (pickle, "_loads"), (_pickle, "loads"))
_UNPICKLER_TARGETS = ((pickle, "Unpickler"), (pickle, "_Unpickler"), (_pickle, "Unpickler"))
_ALL_TARGETS = _LOAD_TARGETS + _LOADS_TARGETS + _UNPICKLER_TARGETS


def snapshot_entry_points():
    """Capture the current value of every entry point fickling patches"""
    return tuple((module, attr, getattr(module, attr)) for module, attr in _ALL_TARGETS)


def restore_entry_points(snapshot):
    """Restore the entry points captured by snapshot_entry_points()"""
    for module, attr, value in snapshot:
        setattr(module, attr, value)


# Captured before patching, for remove_hook().
_originals = snapshot_entry_points()


def _patch_entry_points(load, loads, unpickler):
    """Point every pickle entry point at the given replacements"""
    for targets, replacement in (
        (_LOAD_TARGETS, load),
        (_LOADS_TARGETS, loads),
        (_UNPICKLER_TARGETS, unpickler),
    ):
        for module, attr in targets:
            setattr(module, attr, replacement)


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
    """Replace pickle's load functions and Unpickler by fickling's safe versions"""
    _patch_entry_points(loader.load, loader.loads, FicklingSafetyUnpickler)


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

    class SafeMLUnpickler(FicklingMLUnpickler):
        """Unpickler with pre-configured also_allow list"""

        def __init__(self, file, *args, **kwargs):
            super().__init__(file, *args, also_allow=also_allow, **kwargs)

    _patch_entry_points(new_load, new_loads, SafeMLUnpickler)


def remove_hook():
    """Restore original pickle functions and classes"""
    restore_entry_points(_originals)


# Alias
deactivate_safe_ml_environment = remove_hook
