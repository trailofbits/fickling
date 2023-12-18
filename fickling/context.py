import pickle

import fickling.loader as loader
from fickling.analysis import Severity
from fickling.hook import hook_pickle_load


class FicklingContextManager:
    def __init__(self, max_acceptable_severity=Severity.LIKELY_UNSAFE):
        self.original_pickle_load = pickle.load
        self.max_acceptable_severity = max_acceptable_severity

    def __enter__(self):
        # Modify the `hook_pickle_load` function to use the imported loader
        wrapped_load = lambda file, *args, **kwargs: loader.load(  # noqa
            file, max_acceptable_severity=self.max_acceptable_severity
        )
        pickle.load = hook_pickle_load(wrapped_load)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pickle.load = self.original_pickle_load


def check_safety(print_results=False):
    return FicklingContextManager(print_results)
