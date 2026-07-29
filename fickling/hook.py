import _pickle
import io
import pickle
import sys
import warnings

import fickling.loader as loader
from fickling.ml import FicklingMLUnpickler

# pickle._* are the Python implementations, and are still usable even
# when the C accelerator is loaded.
_LOAD_TARGETS = ((pickle, "load"), (pickle, "_load"), (_pickle, "load"))
_LOADS_TARGETS = ((pickle, "loads"), (pickle, "_loads"), (_pickle, "loads"))
_UNPICKLER_TARGETS = ((pickle, "Unpickler"), (pickle, "_Unpickler"), (_pickle, "Unpickler"))

# Captured before patching, for remove_hook().
_originals = tuple(
    (module, attr, getattr(module, attr))
    for module, attr in _LOAD_TARGETS + _LOADS_TARGETS + _UNPICKLER_TARGETS
)


class StalePickleReferenceWarning(UserWarning):
    """A module holds a pre-hook reference to a pickle entry point, so the hook cannot see it"""


# These re-read _Unpickler from pickle's globals at call time, so a stale reference to one still
# reaches the patched unpickler and is not worth reporting.
_INDIRECT_TARGETS = frozenset({(pickle, "_load"), (pickle, "_loads")})

# id() -> original object, for identity lookups during the sweep.
_ORIGINALS_BY_ID = {
    id(original): original
    for module, attr, original in _originals
    if (module, attr) not in _INDIRECT_TARGETS
}

# Distinct from None, which is a legitimate module attribute value.
_NOT_AN_ORIGINAL = object()

_MAX_REPORTED_REFERENCES = 10


def _find_stale_references():
    """Find `module.attr` bindings still pointing at an unpatched pickle entry point"""
    stale = []
    # Snapshot both levels: a concurrent import would resize them mid-iteration.
    for name, module in list(sys.modules.items()):
        # fickling keeps its own references to the originals on purpose.
        if name == "fickling" or name.startswith("fickling."):
            continue
        # Read __dict__ directly; getattr()/dir() trigger PEP 562 __getattr__ and lazy loaders.
        namespace = getattr(module, "__dict__", None)
        if not isinstance(namespace, dict):
            continue
        for attr, value in list(namespace.items()):
            # Identity, never ==, which would call __eq__ on arbitrary objects.
            if _ORIGINALS_BY_ID.get(id(value), _NOT_AN_ORIGINAL) is value:
                stale.append(f"{name}.{attr}")
    return sorted(stale)


def _warn_stale_references():
    """Warn that some references to pickle escaped the hook, e.g. `from pickle import load`"""
    stale = _find_stale_references()
    if not stale:
        return
    listed = ", ".join(stale[:_MAX_REPORTED_REFERENCES])
    if len(stale) > _MAX_REPORTED_REFERENCES:
        listed += f", and {len(stale) - _MAX_REPORTED_REFERENCES} more"
    warnings.warn(
        "fickling's hook cannot intercept these references, which were bound before it was "
        f"installed: {listed}. Call run_hook() before importing anything that uses pickle.",
        StalePickleReferenceWarning,
        stacklevel=4,
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
    _warn_stale_references()


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
    for module, attr, original in _originals:
        setattr(module, attr, original)


# Alias
deactivate_safe_ml_environment = remove_hook
