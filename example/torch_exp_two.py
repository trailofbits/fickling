from fickling.pytorch import PyTorchModelWrapper
import torch
import torchvision.models as models

model = models.mobilenet_v2()
torch.save(model, "model.pt")
result = PyTorchModelWrapper("model.pt")
# print(dir(result))
pkl = result.pickled
print(dir(pkl))
result = pkl.check_safety.severity