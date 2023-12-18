import warnings

from fickling.fickle import *  # noqa: F403

warnings.warn(
    "As of version 0.0.8, `fickling.pickle` has been renamed `fickling.fickle`. "
    "The `fickling.pickle` module will be removed in a future release!",
    DeprecationWarning,
    stacklevel=2,
)
