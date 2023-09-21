import torch
import zipfile
import io
from fickle import Pickled

from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from typing import Optional


# This is where I'm actually going to test the file 
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


# Uncomment these lines if you no longer have a 'mobilenet_v2.pt' file
#import torchvision.models as models
#model = models.mobilenet_v2()
#torch.save(model, 'mobilenet_v2.pt')
deserialized_model = torch.load('mobilenet_v2.pt')
file_path = 'path/to/pytorch/model.pth'
wrapper = PyTorchModelWrapper('mobilenet_v2.pt')
print(wrapper.pickled)
#wrapper.inject_code('print("Hello, World!")')
#wrapper.save('injected_model.pt')
