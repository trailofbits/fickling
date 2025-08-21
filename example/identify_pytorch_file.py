import torch
import torchvision.models as models

import fickling.polyglot as polyglot

model = models.mobilenet_v2()
torch.save(model, "mobilenet.pth")
torch.save(model, "legacy_mobilenet.pth", _use_new_zipfile_serialization=False)

print("Identifying PyTorch v1.3 file:")
potential_formats = polyglot.identify_pytorch_file_format("mobilenet.pth", print_results=True)

print("Identifying PyTorch v0.1.10 file:")
potential_formats_legacy = polyglot.identify_pytorch_file_format(
    "legacy_mobilenet.pth", print_results=True
)
