import random
import string
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np
import torch
import torchvision.models as models

import fickling.polyglot as polyglot

_lacks_torch_jit_support = sys.version_info >= (3, 14)


def create_pytorch_legacy_tar(tmpdir: Path, tar_file_name: Path):
    # This is an intentional polymock
    storages = tmpdir / "storages"
    tensors = tmpdir / "tensors"
    pickle_file = tmpdir / "pickle"

    storages.mkdir(exist_ok=True)
    tensors.mkdir(exist_ok=True)
    pickle_file.write_text("dummy content")

    with tarfile.open(tar_file_name, mode="w:") as tar:
        tar.add(pickle_file, arcname="pickle")
        tar.add(storages, arcname="storages/")
        tar.add(tensors, arcname="tensors/")

    pickle_file.unlink()
    storages.rmdir()
    tensors.rmdir()


def create_random_zip(tmpdir: Path, filename: Path, size=1024):
    tmp_filename = tmpdir / (
        "".join(random.choices(string.ascii_letters + string.digits, k=10)) + ".tmp"
    )
    tmp_filename.write_bytes(random.randbytes(size))
    with zipfile.ZipFile(filename, "w") as zipf:
        zipf.write(tmp_filename, tmp_filename.name)
    tmp_filename.unlink()


def prepend_random_string(filename: Path, str_length=20):
    random_string = "".join(random.choices(string.ascii_letters + string.digits, k=str_length))
    data = filename.read_bytes()
    filename.write_bytes(random_string.encode() + data)


class TestPolyglotModule(unittest.TestCase):
    def setUp(self):
        random.seed(42)  # Deterministic test data
        self.tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(self.tmpdir.name)

        # Not covered: PyTorch MAR & earlier TorchScript versions

        # PyTorch v1.3
        model = models.mobilenet_v2()
        self.filename_v1_3 = tmppath / "model_v1_3.pth"
        torch.save(model, self.filename_v1_3)

        # PyTorch v1.3 Dup (for testing)
        self.filename_v1_3_dup = tmppath / "model_v1_3_dup.pth"
        torch.save(model, self.filename_v1_3_dup)

        # PyTorch v0.1.10 (Stacked pickle files)
        self.filename_legacy_pickle = tmppath / "model_legacy_pickle.pth"
        torch.save(model, self.filename_legacy_pickle, _use_new_zipfile_serialization=False)

        if not _lacks_torch_jit_support:
            # TorchScript v1.4
            m = torch.jit.script(model)
            self.filename_torchscript = tmppath / "model_torchscript.pt"
            torch.jit.save(m, self.filename_torchscript)

            # TorchScript v1.4 Dup
            self.filename_torchscript_dup = tmppath / "model_torchscript_dup.pt"
            torch.jit.save(m, self.filename_torchscript_dup)

            self.standard_torchscript_polyglot_name = tmppath / "test_polyglot.pt"

        # PyTorch v0.1.1
        self.filename_legacy_tar = tmppath / "model_legacy_tar.pth"
        create_pytorch_legacy_tar(tmppath, self.filename_legacy_tar)

        # Random ZIP file
        self.zip_filename = tmppath / "test_random.zip"
        create_random_zip(tmppath, self.zip_filename)
        prepend_random_string(self.zip_filename)

        # Numpy Not Pickles
        self.numpy_not_pickle = tmppath / "not_pickle.npy"
        np.save(self.numpy_not_pickle, [1, 2, 3])

        self.numpy_pickle = tmppath / "pickle.npy"
        np.save(self.numpy_pickle, {"test": [1, 2, 3]})

        self.tar_numpy_pickle = tmppath / "testtar.anything"
        archive = tarfile.open(self.tar_numpy_pickle, "w")
        archive.add(self.numpy_pickle, arcname="pickle.npy")
        archive.close()

        self.zip_numpy_pickle = tmppath / "testzip.anything"
        archive = zipfile.ZipFile(self.zip_numpy_pickle, "w")
        archive.write(self.numpy_pickle, "pickle.npy")
        archive.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_v1_3(self):
        formats = polyglot.identify_pytorch_file_format(self.filename_v1_3)
        self.assertEqual(formats, ["PyTorch v1.3"])

    # NOTE(boyan): this test doesn't pass but it should. This needs to be fixed.
    # def test_legacy_pickle(self):
    #     formats = polyglot.identify_pytorch_file_format(self.filename_legacy_pickle)
    #     self.assertEqual(formats, ["PyTorch v0.1.10"])

    @unittest.skipIf(_lacks_torch_jit_support, "PyTorch 2.9.1 JIT broken with Python 3.14+")
    def test_torchscript(self):
        formats = polyglot.identify_pytorch_file_format(self.filename_torchscript)
        self.assertEqual(formats, ["TorchScript v1.4", "TorchScript v1.3", "PyTorch v1.3"])

    def test_legacy_tar(self):
        formats = polyglot.identify_pytorch_file_format(
            self.filename_legacy_tar, print_properties=True
        )
        self.assertEqual(formats, ["PyTorch v0.1.1"])

    def test_zip(self):
        formats = polyglot.identify_pytorch_file_format(self.zip_filename)
        self.assertEqual(len(formats), 0)

    def test_recursive_tar(self):
        properties = polyglot.find_file_properties_recursively(self.tar_numpy_pickle)
        proper_result = {
            "is_torch_zip": False,
            "is_tar": True,
            "is_valid_pickle": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_standard_zip": False,
            "is_standard_not_torch": False,
            "has_constants_pkl": False,
            "has_data_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_7z": False,
            "children": {
                "pickle.npy": {
                    "is_torch_zip": False,
                    "is_tar": False,
                    "is_valid_pickle": False,
                    "is_numpy": True,
                    "is_numpy_pickle": True,
                    "is_standard_zip": False,
                    "is_standard_not_torch": False,
                    "has_constants_pkl": False,
                    "has_data_pkl": False,
                    "has_version": False,
                    "has_model_json": False,
                    "has_attributes_pkl": False,
                    "is_7z": False,
                }
            },
        }
        self.assertEqual(properties, proper_result)

    def test_recursive_zip(self):
        properties = polyglot.find_file_properties_recursively(self.zip_numpy_pickle)
        proper_result = {
            "is_torch_zip": True,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_standard_zip": True,
            "is_standard_not_torch": False,
            "has_constants_pkl": False,
            "has_data_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_7z": False,
            "children": {
                "pickle.npy": {
                    "is_torch_zip": False,
                    "is_tar": False,
                    "is_valid_pickle": False,
                    "is_numpy": True,
                    "is_numpy_pickle": True,
                    "is_standard_zip": False,
                    "is_standard_not_torch": False,
                    "has_constants_pkl": False,
                    "has_data_pkl": False,
                    "has_version": False,
                    "has_model_json": False,
                    "has_attributes_pkl": False,
                    "is_7z": False,
                }
            },
        }
        self.assertEqual(properties, proper_result)

    def test_numpy_non_pickle(self):
        properties = polyglot.find_file_properties(self.numpy_not_pickle)
        proper_result = {
            "is_torch_zip": False,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": False,
            "is_standard_not_torch": False,
            "has_data_pkl": False,
            "has_constants_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": True,
            "is_numpy_pickle": False,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    def test_numpy_pickle(self):
        properties = polyglot.find_file_properties(self.numpy_pickle)
        proper_result = {
            "is_torch_zip": False,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": False,
            "is_standard_not_torch": False,
            "has_data_pkl": False,
            "has_constants_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": True,
            "is_numpy_pickle": True,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    def test_v1_3_properties(self):
        properties = polyglot.find_file_properties(self.filename_v1_3)
        proper_result = {
            "is_torch_zip": True,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": True,
            "is_standard_not_torch": False,
            "has_data_pkl": True,
            "has_constants_pkl": False,
            "has_version": True,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    def test_legacy_pickle_properties(self):
        properties = polyglot.find_file_properties(self.filename_v1_3)
        proper_result = {
            "is_torch_zip": True,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": True,
            "is_standard_not_torch": False,
            "has_data_pkl": True,
            "has_constants_pkl": False,
            "has_version": True,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    @unittest.skipIf(_lacks_torch_jit_support, "PyTorch 2.9.1 JIT broken with Python 3.14+")
    def test_torchscript_properties(self):
        properties = polyglot.find_file_properties(self.filename_torchscript)
        proper_result = {
            "is_torch_zip": True,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": True,
            "is_standard_not_torch": False,
            "has_data_pkl": True,
            "has_constants_pkl": True,
            "has_version": True,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    # Previously skipped for Python 3.13 due to numpy private API usage in check_numpy().
    # Fixed in commit 50e206b by switching to public numpy.lib.format APIs.
    def test_zip_properties(self):
        properties = polyglot.find_file_properties(self.zip_filename)
        proper_result = {
            "is_torch_zip": False,
            "is_tar": False,
            "is_valid_pickle": False,
            "is_standard_zip": True,
            "is_standard_not_torch": True,
            "has_constants_pkl": False,
            "has_data_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
            "is_numpy": False,
            "is_numpy_pickle": False,
            "is_7z": False,
        }
        self.assertEqual(properties, proper_result)

    @unittest.skipIf(_lacks_torch_jit_support, "PyTorch 2.9.1 JIT broken with Python 3.14+")
    def test_create_standard_torchscript_polyglot(self):
        polyglot.create_polyglot(
            self.filename_v1_3_dup,
            self.filename_torchscript_dup,
            self.standard_torchscript_polyglot_name,
            print_results=False,
        )
        formats = polyglot.identify_pytorch_file_format(self.standard_torchscript_polyglot_name)
        self.assertTrue({"PyTorch v1.3", "TorchScript v1.4"}.issubset(formats))
