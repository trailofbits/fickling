import pickle

from fickling.analysis import Severity
from fickling.fickle import Pickled


def load(
    file,
    max_acceptable_severity=Severity.LIKELY_UNSAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.load()"""
    pickled_data = Pickled.load(file)
    result = pickled_data.check_safety(
        return_result=True, print_results=print_results, json_output_path=json_output_path
    )
    if result.severity < max_acceptable_severity:
        # We don't do pickle.load(file) because it could allow for a race
        # condition where the file we check is not the same that gets
        # loaded after the analysis.
        return pickle.loads(pickled_data.dumps(), *args, **kwargs)
    else:
        return False