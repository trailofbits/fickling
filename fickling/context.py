import pickle

import fickling.hook as hook
import fickling.loader as loader
from fickling.analysis import Severity


class FicklingContextManager:
    def __init__(self, max_acceptable_severity=Severity.LIKELY_SAFE):
        self.original_pickle_load = pickle.load
        self.max_acceptable_severity = max_acceptable_severity

    def __enter__(self):
        # Modify the `hook_pickle_load` function to use the imported loader
        wrapped_load = lambda file, *args, **kwargs: loader.load(  # noqa
            file, max_acceptable_severity=self.max_acceptable_severity
        )
        hook.run_hook()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pickle.load = self.original_pickle_load


def check_safety():
    return FicklingContextManager()
