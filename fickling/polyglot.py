import torch
from torch.serialization import _is_zipfile
import torchvision.models as models
import zipfile
import os
import random
import string
import tarfile
from fickling.fickle import Pickled, StackedPickle

"""
We currently support the following PyTorch file formats: 
• PyTorch v0.1.1: Tar file with sys_info, pickle, storages, and tensors
• PyTorch v0.1.10: Stacked pickle files
• TorchScript v1.0: ZIP file with model.json and constants.pkl (a JSON file and a pickle file)
• TorchScript v1.1: ZIP file with model.json and attribute.pkl (a JSON file and a pickle file)
• TorchScript v1.3: ZIP file with data.pkl and constants.pkl (2 pickle files)
• TorchScript v1.4: ZIP file with data.pkl, constants.pkl, and version (2 pickle files and a folder)
• PyTorch v1.3: ZIP file containing data.pkl (1 pickle file)
• PyTorch model archive format: ZIP file that includes Python code files and pickle files

This description draws from this PyTorch GitHub issue: https://github.com/pytorch/pytorch/issues/31877. 
If any inaccuracies in that description are found or new file formats are established, that should be reflected. 

We are intentionally matching the semantics of the PyTorch reference parsers. 

Reference: https://github.com/lutzroeder/netron/blob/main/source/pytorch.js
"""


def file_exists_in_zip(zip_path, file_name_or_extension, extension=False):
    try:
        with zipfile.ZipFile(zip_path) as zip_file:
            if extension:
                return any(entry.endswith(file_name_or_extension) for entry in zip_file.namelist())
            else:
                return any(file_name_or_extension in entry for entry in zip_file.namelist())
    except zipfile.BadZipFile:
        print(f"Invalid ZIP file: {zip_path}")
        return False
    except FileNotFoundError:
        print(f"File not found: {zip_path}")
        return False


def check_pickle_validity(file, loader):
    try:
        loader(file)
        return True
    except:
        return False


def check_if_pytorch_legacy_format(file_path):
    required_entries = {"pickle", "storages", "tensors"}
    try:
        with tarfile.open(file_path, mode="r:", format=tarfile.PAX_FORMAT) as tar:
            tar_contents = {member.name for member in tar.getmembers()}
            print(tar_contents)
            return required_entries.issubset(tar_contents)
    except Exception as e:
        return False


def find_file_characteristics(file, print_characteristics=False):
    characteristics = {}
    with open(file, "rb") as file:
        is_torch_zip = _is_zipfile(file)
        characteristics["is_torch_zip"] = is_torch_zip

        # This tarfile check has many false positivies. It is not a determinant of PyTorch v0.1.1.
        is_tar = tarfile.is_tarfile(file)
        characteristics["is_tar"] = is_tar

        # This is here as a baseline. Custom unpickling in PyTorch makes this check not helpful for PyTorch v0.1.10.
        # In the future, we can implement these unpicklers for deeper analysis.
        is_valid_pickle = check_pickle_validity(file, Pickled.load)
        is_valid_stacked_pickle = check_pickle_validity(file, StackedPickle.load)
        characteristics["is_valid_pickle"] = is_valid_pickle
        characteristics["is_valid_stacked_pickle"] = is_valid_stacked_pickle

        is_standard_zip = zipfile.is_zipfile(file)
        characteristics["is_standard_zip"] = is_standard_zip

        is_standard_not_torch = is_standard_zip and not is_torch_zip
        characteristics["is_standard_not_torch"] = is_standard_not_torch

        torch_zip_results = {
            "has_constants_pkl": False,
            "has_data_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attribute_pkl": False,
        }
        if is_torch_zip:
            torch_zip_checks = [
                "data.pkl",
                "constants.pkl",
                "version",
                "model.json",
                "attribute.pkl",
            ]
            torch_zip_results = {
                f"has_{'_'.join(f.split('.'))}": file_exists_in_zip(file, f)
                for f in torch_zip_checks
            }
        characteristics.update(torch_zip_results)
    if print_characteristics:
        print("\nCharacteristics:", characteristics, "\n")
    return characteristics


# TODO interface with the PyTorch module
def identify_pytorch_file_format(file, print_characteristics=False):
    characteristics = find_file_characteristics(file, print_characteristics)
    formats = []
    corrupted = False

    if characteristics["is_torch_zip"]:
        format_conditions = [
            (["has_data_pkl", "has_constants_pkl", "has_version"], "TorchScript v1.4"),
            (["has_data_pkl", "has_constants_pkl"], "TorchScript v1.3"),
            (["has_model_json", "has_constants_pkl"], "TorchScript v1.0"),
            (["has_model_json", "has_attribute_pkl"], "TorchScript v1.1"),
            (["has_data_pkl"], "PyTorch v1.3"),
        ]
        formats = [
            format_name
            for keys, format_name in format_conditions
            if all(characteristics[key] for key in keys)
        ]
        # Consider expanding corruption cases to include any case with extraneous files
        if (
            characteristics["has_model_json"]
            and not characteristics["has_attribute_pkl"]
            and not characteristics["has_constants_pkl"]
        ):
            corrupted = True
            corrupted_error = "Your file may be corrupted. It contained a model.json file without an attributes.pkl or constants.pkl file."
    if characteristics["is_valid_pickle"] or characteristics["is_valid_stacked_pickle"]:
        formats.append("PyTorch v0.1.10")
    if characteristics["is_tar"]:
        is_pytorch_legacy_format = check_if_pytorch_legacy_format(file)
        if is_pytorch_legacy_format:
            formats.append("PyTorch v0.1.1")
    if characteristics["is_standard_zip"]:
        has_json = file_exists_in_zip(file, ".json")
        has_serialized_model = file_exists_in_zip(file, ".pt") or file_exists_in_zip(file, ".pth")
        has_code = file_exists_in_zip(file, ".py")
        if has_json and has_serialized_model and has_code:
            # Reference: https://pytorch.org/serve/getting_started.html
            # Reference: https://github.com/pytorch/serve/tree/master/model-archiver
            formats.append("PyTorch model archive format")
    if corrupted:
        print(corrupted_error)
    if len(formats) != 0:
        # Show the most likely file format as well as secondary file formats
        primary = formats[0]
        print("Your file is most likely: ", primary, "\n")
        secondary = formats[1:]
        if len(secondary) != 0:
            print("The following file formats may also be valid: ", secondary)
    else:
        print("Your file may not be a PyTorch file. No valid file formats were detected.")
    return formats


# filename = "scriptmodule.pt"
# filename = "legacy_model.pth"
# filename = "model.pth"
# filename = "random_data.zip"
# filename = "pytorch_legacy.tar"
# filename = "densenet161.mar"
# identify_pytorch_file_format(filename, True)
