import tempfile
import unittest
from pathlib import Path

import torch
import torchvision.models as models

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

    def test_force_on_unidentified_file_does_not_crash(self):
        # Regression: force=True on an unrecognized file must warn and proceed
        # (reporting no identified formats) instead of raising IndexError from
        # indexing an empty formats list in validate_file_format().
        bogus = Path(self.tmpdir.name) / "not_a_pytorch_file.bin"
        bogus.write_bytes(b"definitely not a pytorch file, just random bytes 123")

        # Without force, an unidentified file is rejected with a clear ValueError.
        with self.assertRaises(ValueError):
            PyTorchModelWrapper(bogus).validate_file_format()

        # With force=True it must not raise (only warn) and report no formats.
        with self.assertWarns(UserWarning):
            formats = PyTorchModelWrapper(bogus, force=True).validate_file_format()
        self.assertEqual(list(formats), [])
