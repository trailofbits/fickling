from fickling.hook import PickleFinder
import sys

sys.meta_path.insert(0, PickleFinder())  # insert our finder as the first

if 'pickle' in sys.modules:
    del sys.modules['pickle']
    pass 

import pickle

with open("test.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

