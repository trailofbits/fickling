import torch
import torchvision.models as models

from fickling.hook import HookManager

# TODO Figure out what to do about the Torch hook

hook_manager = HookManager()
hook_manager.run_hook_with_torch()

# hook.run_hook_with_torch()
model = models.mobilenet_v2()

torch.save(model, "model.pt")
torch.save(model, "legacy_model.pt", _use_new_zipfile_serialization=False)

print("MODEL")
torch.load("model.pt")
print("LEGACY MODEL")
torch.load("legacy_model.pt")
