# fmt: off
from .loader import load #noqa
from .context import check_safety #noqa
from .hook import check_always #noqa
# fmt: on

# The above lines enables `fickling.load()` and `with fickling.check_safety()`
# The comments are necessary to comply with linters
__version__ = "0.0.8"
