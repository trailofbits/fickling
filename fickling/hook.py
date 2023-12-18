import pickle

import fickling.loader as loader


def hook_pickle_load(*args, **kwargs):
    # Wraps the function to actually run the core loader
    def wrapper(*args, **kwargs):
        return loader.load(*args, **kwargs)

    return wrapper


def run_hook(*args, **kwargs):
    pickle.load = hook_pickle_load(*args, **kwargs)
