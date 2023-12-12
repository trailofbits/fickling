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

    def tearDown(self):
        for filename in [self.filename_v1_3, self.zip_filename]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_wrapper(self):
        try:
            PyTorchModelWrapper(self.filename_v1_3)
        except Exception as e:  # noqa
            self.fail(f"PyTorchModelWrapper was not able to load a PyTorch v1.3 file: {e}")

    def test_pickled(self):
        result = PyTorchModelWrapper(self.filename_v1_3)
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
