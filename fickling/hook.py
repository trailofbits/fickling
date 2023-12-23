import pickle

import fickling.loader as loader


def run_hook():
    """Replace pickle.load() by fickling's load()"""
    pickle.load = loader.load

def check_always():
    """
    Alias for run_hook()
    """
    run_hook()