import os
import pickle

import numpy

import fickling.hook as hook

# Set up global fickling hook
hook.run_hook()

# Fickling can check a pickle file for safety prior to running it
test_list = [1, 2, 3]

# Create "safe" pickle file
with open("safe.pkl", "wb") as file:
    pickle.dump(test_list, file)


class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))


payload = Payload()

print("\n\nLoading unsafe file using numpy.load:\n\n")
with open("unsafe.pickle", "wb") as f:
    pickle.dump(payload, f)


print("\n\nLoading safe file:\n\n")
with open("safe.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)


# Create "unsafe" pickle file
class Payload:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))


payload = Payload()

print("\n\nLoading unsafe file using numpy.load:\n\n")
with open("unsafe.pickle", "wb") as f:
    pickle.dump(payload, f)

# This hook works when pickle.load is called under the hood in Python as well
# Note that this does not always work for torch.load()
numpy.load("unsafe.pickle", allow_pickle=True)

# TODO This is throwaway code meant to temporarily demo how this works on torch.load()

import torch
import torchvision.models as models

model = models.mobilenet_v2()

torch.save(model, "model.pt")
torch.save(model, "legacy_model.pt", _use_new_zipfile_serialization=False)
print("\n\nMODEL\n\n")
torch.load("model.pt")
print("LEGACY MODEL")
torch.load("legacy_model.pt")