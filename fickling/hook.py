import pickle
import fickling.loader as loader

def run_hook():
    pickle.load = loader.load