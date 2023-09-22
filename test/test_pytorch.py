import torchvision.models as models
import torch 
from fickling.pytorch import PyTorchModelWrapper
from unittest import TestCase


class PyTorchTestCase(TestCase):
    def setUp(self):
        self.model = models.mobilenet_v2()
        self.file_path = 'mobilenet_v2.pt'
        torch.save(self.model, self.file_path)
        deserialized_model = torch.load('mobilenet_v2.pt')
        self.wrapper = PyTorchModelWrapper('mobilenet_v2.pt')

    def test_torch_loading(self):
        self.assertIsInstance(self.wrapper, PyTorchModelWrapper)

    def test_fallback_injection(self):
        payload = '''print("Hello, World!")'''
        self.wrapper.inject_payload(payload, 'altered_model.pt')
        torch.load('altered_model.pt')
