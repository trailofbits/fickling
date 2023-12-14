from fickling.fickle import Pickled
import pickle 

def hook_pickle_load(pickle_load_function):
    def wrapper(*args, **kwargs):
        file = args[0]
        pickled_data = Pickled.load(file)
        if pickled_data.is_likely_safe is True:
            print("This is likely safe")
            return pickle.loads(pickled_data.dumps())
        else:
            print("Unsafe!")
            return None
    return wrapper

def run_hook():
    pickle.load = hook_pickle_load(pickle.load)