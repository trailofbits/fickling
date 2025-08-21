import os
import unittest

import torch
import torchvision.models as models

from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper


class TestPyTorchModule(unittest.TestCase):
    def setUp(self):
        model = models.mobilenet_v2()
        self.filename_v1_3 = "test_model.pth"
        torch.save(model, self.filename_v1_3)
        self.zip_filename = "test_random_data.zip"
        m = torch.jit.script(model)
        self.torchscript_filename = "test_model_torchscript.pth"
        torch.jit.save(m, self.torchscript_filename)

    def tearDown(self):
        for filename in [self.filename_v1_3, self.zip_filename, self.torchscript_filename]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_wrapper(self):
        try:
            PyTorchModelWrapper(self.filename_v1_3)
        except Exception as e:  # noqa
            self.fail(f"PyTorchModelWrapper was not able to load a PyTorch v1.3 file: {e}")

    def test_torchscript_wrapper(self):
        try:
            PyTorchModelWrapper(self.torchscript_filename)
        except Exception as e:  # noqa
            self.fail(f"PyTorchModelWrapper was not able to load a TorchScript v1.4 file: {e}")

    def test_pickled(self):
        result = PyTorchModelWrapper(self.filename_v1_3)
        pickled_portion = result.pickled
        self.assertIsInstance(pickled_portion, Pickled)

    def test_torchscript_pickled(self):
        result = PyTorchModelWrapper(self.torchscript_filename)
        pickled_portion = result.pickled
        self.assertIsInstance(pickled_portion, Pickled)

    def test_injection_insertion(self):
        try:
            result = PyTorchModelWrapper(self.filename_v1_3)
            temp_filename = "temp_filename"
            result.inject_payload("print('Hello, World!')", temp_filename, injection="insertion")
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
        except Exception as e:  # noqa
            self.fail(
                f"PyTorchModelWrapper was not able to inject code into a PyTorch v1.3 file: {e}"
            )

    def test_injection_combination(self):
        try:
            result = PyTorchModelWrapper(self.filename_v1_3)
            temp_filename = "temp_filename"
            result.inject_payload("print('Hello, World!')", temp_filename, injection="combination")
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
        except Exception as e:  # noqa
            self.fail(
                f"PyTorchModelWrapper was not able to inject code into a PyTorch v1.3 file: {e}"
            )
