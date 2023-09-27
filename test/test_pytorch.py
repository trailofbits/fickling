import torchvision.models as models
import torch 
from fickling.pytorch import PyTorchModelWrapper
from unittest import TestCase
import os


class PyTorchTestCase(TestCase):
    def setUp(self):
        self.model = models.mobilenet_v2()
        self.file_path = 'mobilenet_v2.pt'
        torch.save(self.model, self.file_path)
        deserialized_model = torch.load('mobilenet_v2.pt')
        self.wrapper = PyTorchModelWrapper('mobilenet_v2.pt')
        self.output_path = 'altered_model.pt'

    def test_torch_loading(self):
        self.assertIsInstance(self.wrapper, PyTorchModelWrapper)

    def test_fallback_injection(self):
        payload = '''print("Hello, World!")'''
        self.wrapper.inject_payload(payload, self.output_path, injection="reduce")
        torch.load(self.output_path)
    
    def tearDown(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        if os.path.exists(self.output_path):
            os.remove(self.output_path)
