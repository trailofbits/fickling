import pickle

import fickling.loader as loader


def run_hook():
    # This is the global function hook
    pickle.load = loader.load
