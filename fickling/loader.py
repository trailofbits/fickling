import pickle

from fickling.analysis import Severity
from fickling.fickle import Pickled


def load(file, max_acceptable_severity=Severity.LIKELY_UNSAFE, *args, **kwargs):
    """Exposed as fickling.load()"""
    pickled_data = Pickled.load(file)
    result = pickled_data.check_safety()
    if result <= max_acceptable_severity:
        # We don't do pickle.load(file) because it could allow for a race
        # condition where the file we check is not the same that gets
        # loaded after the analysis.
        return pickle.loads(pickled_data.dumps(), *args, **kwargs)
    else:
        return False
