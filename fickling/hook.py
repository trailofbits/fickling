import pickle

import fickling.loader as loader


def hook_pickle_load(pickle_load_function):
    # Wraps the function to actually run the core loader
    def wrapper(*args, **kwargs):
        file = args[0]
        return loader.load(file)

    return wrapper


def run_hook():
    pickle.load = hook_pickle_load(pickle.load)
