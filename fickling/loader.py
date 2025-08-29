import pickle

from fickling.analysis import Severity, check_safety
from fickling.exception import UnsafeFileError
from fickling.fickle import Pickled


def load(
    file,
    max_acceptable_severity=Severity.LIKELY_SAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.load()"""
    pickled_data = Pickled.load(file, fail_on_decode_error=False)
    result = check_safety(pickled=pickled_data, json_output_path=json_output_path)
    if result.severity <= max_acceptable_severity and not pickled_data.has_invalid_opcode:
        # We don't do pickle.load(file) because it could allow for a race
        # condition where the file we check is not the same that gets
        # loaded after the analysis.
        return pickle.loads(pickled_data.dumps(), *args, **kwargs)
    if pickled_data.has_invalid_opcode:
        raise UnsafeFileError(
            file,
            "This file contains an invalid opcode sequence. It is "
            "either corrupted or maliciously attempting to bypass "
            "pickle analysis tools",
        )
    raise UnsafeFileError(file, result.to_dict())
