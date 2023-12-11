import os
import warnings
import zipfile
from pathlib import Path
from typing import Optional

import torch

import fickling.polyglot
from fickling.fickle import Pickled


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
    def __init__(self, path: Path, force: bool = False):
        self.path: Path = path
        self._pickled: Optional[Pickled] = None
        self.force: bool = force

    def validate_file_format(self):
        formats = fickling.polyglot.identify_pytorch_file_format(self.path)
        """
        One option was to raise an error if PyTorch v1.3 was not found
        or if any of the TorchScript versions were found.
        However, that would prevent polyglots from being loaded.
        Therefore, the 'force' argument was created to enable users to do that if needed.
        Another option was to warn only if "PyTorch v1.3" was not the most likely format.
        Instead, the file formats are directly specified for clarity and independence.
        """
        if len(formats) == 0:
            if self.force is True:
                warnings.warn(
                    """
                    This file has not been identified as a PyTorch file.
                    If it is a PyTorch file, raise an issue on GitHub
                    """,
                    UserWarning,
                )
            else:
                raise ValueError(
                    """
                    This file has not been identified as a PyTorch file.
                    If it is a PyTorch file, raise an issue on GitHub.
                    """
                )
        if ("PyTorch v1.3" not in formats) or {
            "TorchScript v1.4",
            "TorchScript v1.3",
            "TorchScript v1.1",
            "TorchScript v1.0",
        }.intersection(formats):
            if "PyTorch v0.1.10" in formats:
                if self.force is True:
                    warnings.warn(
                        """
                        This file may be a PyTorch v0.1.10 file.
                        Try Pickled.load() or StackedPickle.load() if this fails
                        """,
                        UserWarning,
                    )
                else:
                    raise ValueError(
                        """
                        This file may be a PyTorch v0.1.10 file.
                        Try Pickled.load() or StackedPickle.load() instead
                        or use the argument `force=True`.
                        """
                    )
            else:
                if self.force is True:
                    warnings.warn(
                        """A fickling wrapper and injection method does not exist for that format.
                        Please raise an issue on our GitHub.""",
                        UserWarning,
                    )
                else:
                    raise NotImplementedError(
                        """A fickling wrapper and injection method does not exist for that format.
                        Please raise an issue on our GitHub or use the argument `force=True`."""
                    )
        return

    @property
    def pickled(self) -> Pickled:
        if self._pickled is None:
            self.validate_file_format()
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
        # TODO Replace output_path and default injection argument and order of arguments

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
