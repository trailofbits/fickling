import torch
import torchvision.models as models

from fickling.pytorch import PyTorchModelWrapper

# Load example PyTorch model
model = models.mobilenet_v2()
torch.save(model, "mobilenet.pth")

# Wrap model file into fickling
result = PyTorchModelWrapper("mobilenet.pth")

# Inject payload, overwriting the existing file instead of creating a new one
temp_filename = "temp_filename.pt"
result.inject_payload(
    "print('!!!!!!Never trust a pickle!!!!!!')",
    temp_filename,
    injection="insertion",
    overwrite=True,
)

# Load file with injected payload
torch.load("mobilenet.pth")
