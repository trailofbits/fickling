import _pickle
import io
import pickle
import sys
import warnings
from types import ModuleType

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


class StalePickleReferenceWarning(UserWarning):
    """A module holds a pre-hook reference to a pickle entry point, so the hook cannot see it"""


# These re-read _Unpickler from pickle's globals at call time, so a stale reference to one still
# reaches the patched unpickler and is not worth reporting.
_INDIRECT_TARGETS = frozenset({(pickle, "_load"), (pickle, "_loads")})

# _originals keeps these objects alive for identity checks during the sweep.
_ORIGINAL_IDS = {
    id(original) for module, attr, original in _originals if (module, attr) not in _INDIRECT_TARGETS
}

_MAX_REPORTED_REFERENCES = 10


def _find_stale_references():
    """Find `module.attr` bindings still pointing at an unpatched pickle entry point"""
    stale = []
    # Snapshot both levels: a concurrent import would resize them mid-iteration.
    for name, module in list(sys.modules.items()):
        # fickling keeps its own references to the originals on purpose.
        if name == "fickling" or name.startswith("fickling."):
            continue
        # Module subclasses can initialize a lazy module even when reading __dict__.
        if type(module) is not ModuleType:
            continue
        for attr, value in list(vars(module).items()):
            # The hook will replace its own target bindings immediately after the scan.
            if id(value) in _ORIGINAL_IDS and (module, attr) not in _ALL_TARGETS:
                stale.append(f"{name}.{attr}")
    return sorted(stale)


def _warn_stale_references():
    """Warn about module globals that the hook will leave pointing to the original functions."""
    stale = _find_stale_references()
    if not stale:
        return
    listed = ", ".join(stale[:_MAX_REPORTED_REFERENCES])
    if len(stale) > _MAX_REPORTED_REFERENCES:
        listed += f", and {len(stale) - _MAX_REPORTED_REFERENCES} more"
    warnings.warn(
        f"fickling's hook cannot intercept these references: {listed}. "
        "Install the hook before importing libraries that use pickle.",
        StalePickleReferenceWarning,
        stacklevel=3,
    )


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


def run_hook(*, warn_on_stale_references: bool = False):
    """Replace pickle's load functions and Unpickler by fickling's safe versions"""
    if warn_on_stale_references:
        _warn_stale_references()
    _patch_entry_points(loader.load, loader.loads, FicklingSafetyUnpickler)


always_check_safety = run_hook


def activate_safe_ml_environment(
    also_allow=None, *, allow_nested_unpicklers: bool = True, warn_on_stale_references: bool = False
):
    """Enforce using the ML whitelist unpickler"""

    class SafeMLUnpickler(FicklingMLUnpickler):
        """Unpickler with pre-configured also_allow list and nested unpickler policy"""

        _allow_nested_unpicklers = allow_nested_unpicklers

        def __init__(self, file, *args, **kwargs):
            super().__init__(file, *args, also_allow=also_allow, **kwargs)

    def new_load(file, *args, **kwargs):
        return SafeMLUnpickler(file, **kwargs).load(*args)

    def new_loads(data, *args, **kwargs):
        return new_load(io.BytesIO(data), *args, **kwargs)

    if warn_on_stale_references:
        _warn_stale_references()
    _patch_entry_points(new_load, new_loads, SafeMLUnpickler)


def remove_hook():
    """Restore original pickle functions and classes"""
    restore_entry_points(_originals)


# Alias
deactivate_safe_ml_environment = remove_hook
