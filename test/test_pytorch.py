import tempfile
import unittest
from pathlib import Path
from unittest import mock

import torch
import torchvision.models as models

import fickling.polyglot
from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestPyTorchModule(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(self.tmpdir.name)

        model = models.mobilenet_v2()
        self.filename_v1_3 = tmppath / "test_model.pth"
        torch.save(model, self.filename_v1_3)

        # Pre-generated fixture to avoid torch.jit deprecation warnings
        self.torchscript_filename = FIXTURES_DIR / "squeezenet1_0_torchscript_v1_4.pt"

    def tearDown(self):
        self.tmpdir.cleanup()

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


class TestUnidentifiedFile(unittest.TestCase):
    def test_force_on_unidentified_file_does_not_crash(self):
        with mock.patch.object(fickling.polyglot, "identify_pytorch_file_format", return_value=[]):
            wrapper = PyTorchModelWrapper(Path("does_not_exist.bin"), force=True)
            with self.assertWarnsRegex(UserWarning, "not been identified"):
                self.assertEqual(wrapper.validate_file_format(), [])
