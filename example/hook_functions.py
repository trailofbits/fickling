import os
import pickle

import numpy

import fickling

# Set up global fickling hook
fickling.always_check_safety()
# Eauivalent to fickling.hook.run_hook()

# Fickling can check a pickle file for safety prior to running it
test_list = [1, 2, 3]

# Create a "safe" and "unsafe" file
with open("safe.pkl", "wb") as file:
    pickle.dump(test_list, file)


class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))


payload = Payload()

with open("unsafe.pkl", "wb") as f:
    pickle.dump(payload, f)


print("\n\nLoading safe file:\n\n")
with open("safe.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

print("\n\nLoading unsafe file using numpy.load:\n\n")
with open("unsafe.pkl", "wb") as f:
    pickle.dump(payload, f)

# This hook works when pickle.load is called under the hood in Python as well
# Note that this does not always work for torch.load()
# This should raise "UnsafeFileError"
numpy.load("unsafe.pkl", allow_pickle=True)
