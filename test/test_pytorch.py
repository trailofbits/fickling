import sys
import tempfile
import unittest
from pathlib import Path

import torch
import torchvision.models as models

from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper

_lacks_torch_jit_support = sys.version_info >= (3, 14)


class TestPyTorchModule(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2()
        self.filename_v1_3 = tmppath / "test_model.pth"
        torch.save(model, self.filename_v1_3)

        if not _lacks_torch_jit_support:
            m = torch.jit.script(model)
            self.torchscript_filename = tmppath / "test_model_torchscript.pth"
            torch.jit.save(m, self.torchscript_filename)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_wrapper(self):
        try:
            PyTorchModelWrapper(self.filename_v1_3)
        except Exception as e:  # noqa
            self.fail(f"PyTorchModelWrapper was not able to load a PyTorch v1.3 file: {e}")

    @unittest.skipIf(_lacks_torch_jit_support, "PyTorch 2.9.1 JIT broken with Python 3.14+")
    def test_torchscript_wrapper(self):
        try:
            PyTorchModelWrapper(self.torchscript_filename)
        except Exception as e:  # noqa
            self.fail(f"PyTorchModelWrapper was not able to load a TorchScript v1.4 file: {e}")

    def test_pickled(self):
        result = PyTorchModelWrapper(self.filename_v1_3)
        pickled_portion = result.pickled
        self.assertIsInstance(pickled_portion, Pickled)

    @unittest.skipIf(_lacks_torch_jit_support, "PyTorch 2.9.1 JIT broken with Python 3.14+")
    def test_torchscript_pickled(self):
        result = PyTorchModelWrapper(self.torchscript_filename)
        pickled_portion = result.pickled
        self.assertIsInstance(pickled_portion, Pickled)

    def test_injection_insertion(self):
        try:
            result = PyTorchModelWrapper(self.filename_v1_3)
            temp_filename = Path(self.tmpdir.name) / "temp_filename"
            result.inject_payload("print('Hello, World!')", temp_filename, injection="insertion")
        except Exception as e:  # noqa
            self.fail(
                f"PyTorchModelWrapper was not able to inject code into a PyTorch v1.3 file: {e}"
            )

    def test_injection_combination(self):
        try:
            result = PyTorchModelWrapper(self.filename_v1_3)
            temp_filename = Path(self.tmpdir.name) / "temp_filename"
            result.inject_payload("print('Hello, World!')", temp_filename, injection="combination")
        except Exception as e:  # noqa
            self.fail(
                f"PyTorchModelWrapper was not able to inject code into a PyTorch v1.3 file: {e}"
            )
