# fmt: off
from .loader import load #noqa
from .context import check_safety #noqa
# fmt: on

# The above lines enables `fickling.load()` and `with fickling.check_safety()`
# The comments are necessary to comply with linters
__version__ = "0.0.8"
