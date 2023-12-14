import fickling.hook as hook
import pickle
import numpy 
import os

# Set up global fickling hook
hook.run_hook()

# Fickling can check a pickle file for safety prior to running it
test_list = [1, 2, 3]

# Create "safe" pickle file
with open('safe.pkl', 'wb') as file:
    pickle.dump(test_list, file)

# Load "safe" pickle file
with open("safe.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

# Create "unsafe" pickle file
class Payload(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))

payload = Payload()

# Load "unsafe" pickle file
with open("unsafe.pickle", "wb") as f:
    pickle.dump(payload, f)

# This hook works when pickle.load is called under the hood in Python as well 
numpy.load("unsafe.pickle", allow_pickle=True)
