import os
import random
import string
import tarfile
import unittest
import zipfile

import torch
import torchvision.models as models

import numpy as np

import fickling.polyglot as polyglot


def create_pytorch_legacy_tar(tar_file_name):
    # This is an intentional polymock
    os.makedirs("storages", exist_ok=True)
    os.makedirs("tensors", exist_ok=True)
    with open("pickle", "w") as f:
        f.write("dummy content")
    with tarfile.open(tar_file_name, mode="w:") as tar:
        tar.add("pickle")
        tar.add("storages", arcname="storages/")
        tar.add("tensors", arcname="tensors/")
    os.remove("pickle")
    os.rmdir("storages")
    os.rmdir("tensors")


def create_random_zip(filename, size=1024):
    tmp_filename = "".join(random.choices(string.ascii_letters + string.digits, k=10)) + ".tmp"
    with open(tmp_filename, "wb") as f:
        f.write(os.urandom(size))
    with zipfile.ZipFile(filename, "w") as zipf:
        zipf.write(tmp_filename)
    os.remove(tmp_filename)


def prepend_random_string(filename, str_length=20):
    random_string = "".join(random.choices(string.ascii_letters + string.digits, k=str_length))
    with open(filename, "rb") as original_file:
        data = original_file.read()
    with open(filename, "wb") as modified_file:
        modified_file.write(random_string.encode() + data)


class TestPolyglotModule(unittest.TestCase):
    def setUp(self):
        # Not covered: PyTorch MAR & earlier TorchScript versions

        # PyTorch v1.3
        model = models.mobilenet_v2()
        self.filename_v1_3 = "model_v1_3.pth"
        torch.save(model, self.filename_v1_3)

        # PyTorch v1.3 Dup (for testing)
        self.filename_v1_3_dup = "model_v1_3_dup.pth"
        torch.save(model, self.filename_v1_3_dup)

        # PyTorch v0.1.10 (Stacked pickle files)
        self.filename_legacy_pickle = "model_legacy_pickle.pth"
        torch.save(model, self.filename_legacy_pickle, _use_new_zipfile_serialization=False)

        # TorchScript v1.4
        m = torch.jit.script(model)
        self.filename_torchscript = "model_torchscript.pt"
        torch.jit.save(m, self.filename_torchscript)

        # TorchScript v1.4
        self.filename_torchscript_dup = "model_torchscript_dup.pt"
        torch.jit.save(m, self.filename_torchscript_dup)

        # PyTorch v0.1.1
        self.filename_legacy_tar = "model_legacy_tar.pth"
        create_pytorch_legacy_tar(self.filename_legacy_tar)

        # Random ZIP file
        self.zip_filename = "test_random.zip"
        create_random_zip(self.zip_filename)
        prepend_random_string(self.zip_filename)

        # Numpy Not Pickles
        self.numpy_not_pickle = "not_pickle.npy"
        np.save(self.numpy_not_pickle, [1, 2, 3])

        self.numpy_pickle = "pickle.npy"
        np.save(self.numpy_pickle, {"test": [1, 2, 3]})

        self.tar_numpy_pickle = "testtar.anything"
        archive = tarfile.open(self.tar_numpy_pickle, "w")
        archive.add(self.numpy_pickle)
        archive.close()

        self.zip_numpy_pickle = "testzip.anything"
        archive = zipfile.ZipFile(self.zip_numpy_pickle, "w")
        archive.write(self.numpy_pickle, self.numpy_pickle)
        archive.close()

        self.standard_torchscript_polyglot_name = "test_polyglot.pt"

    def tearDown(self):
        for filename in [
            self.filename_v1_3,
            self.filename_legacy_pickle,
            self.filename_torchscript,
            self.filename_legacy_tar,
            self.zip_filename,
            self.filename_torchscript_dup,
            self.filename_v1_3_dup,
            self.standard_torchscript_polyglot_name,
            self.numpy_not_pickle,
            self.numpy_pickle,
            self.tar_numpy_pickle,
            self.zip_numpy_pickle,
        ]:
            if os.path.exists(filename):
                os.remove(filename)

    def test_v1_3(self):
        formats = polyglot.identify_pytorch_file_format(self.filename_v1_3)
        self.assertEqual(formats, ["PyTorch v1.3"])

    def test_legacy_pickle(self):
        formats = polyglot.identify_pytorch_file_format(self.filename_legacy_pickle)
        self.assertEqual(formats, ["PyTorch v0.1.10"])

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
        }
        self.assertEqual(properties, proper_result)

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
        }
        self.assertEqual(properties, proper_result)

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
        }
        self.assertEqual(properties, proper_result)

    def test_create_standard_torchscript_polyglot(self):
        polyglot.create_polyglot(
            self.filename_v1_3_dup,
            self.filename_torchscript_dup,
            self.standard_torchscript_polyglot_name,
            print_results=False,
        )
        formats = polyglot.identify_pytorch_file_format(self.standard_torchscript_polyglot_name)
        self.assertTrue({"PyTorch v1.3", "TorchScript v1.4"}.issubset(formats))
