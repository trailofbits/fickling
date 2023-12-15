import fickling.hook as hook
import pickle
import numpy 
import os
from fickling.context import FicklingContextManager
import torchvision.models as models
import torch
# Set up global fickling hook
hook.run_hook()
model = models.mobilenet_v2()

torch.save(model, "model.pt")
torch.save(model,  "legacy_model.pt", _use_new_zipfile_serialization=False)

print("MODEL")
torch.load("model.pt")
print("LEGACY MODEL")
torch.load("legacy_model.pt")
