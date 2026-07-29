import pickle

import fickling.hook as hook


class FicklingContextManager:
    def __init__(self):
        self.original_pickle_load = pickle.load

    def __enter__(self):
        hook.run_hook()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pickle.load = self.original_pickle_load


def check_safety():
    return FicklingContextManager()
