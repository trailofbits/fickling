from fickling.fickle import Pickled
import pickle 

def core_load(file, run_after_analysis=True):
    pickled_data = Pickled.load(file)
    results = pickled_data.check_safety
    #print(results)
    if pickled_data.is_likely_safe is True:
        #print("This is likely safe")
        # Apply a fallback in case of custom unpicklers unknown to the user
        if run_after_analysis is True:
            try:
                return pickle.loads(pickled_data.dumps())
            except Exception:
                raise ValueError("""The data could not be dumped and pickled. 
                                 Try `run_after_analysis=False` and run 
                                 the custom unpickling after.""")
        else:
            return True
    else:
        #print("This is unsafe!")
        return False

def hook_pickle_load(pickle_load_function):
    def wrapper(*args, **kwargs):
        file = args[0]
        return core_load(file)
    return wrapper

def run_hook():
    pickle.load = hook_pickle_load(pickle.load)