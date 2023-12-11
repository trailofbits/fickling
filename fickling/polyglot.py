import tarfile
import zipfile
import torch
from torch.serialization import _is_zipfile

from fickling.fickle import Pickled, StackedPickle

"""
PyTorch file format identification:

We currently support the following PyTorch file formats:
• PyTorch v0.1.1: Tar file with sys_info, pickle, storages, and tensors
• PyTorch v0.1.10: Stacked pickle files
• TorchScript v1.0: ZIP file with model.json and constants.pkl (a JSON file and a pickle file)
• TorchScript v1.1: ZIP file with model.json and attribute.pkl (a JSON file and a pickle file)
• TorchScript v1.3: ZIP file with data.pkl and constants.pkl (2 pickle files)
• TorchScript v1.4: ZIP file with data.pkl, constants.pkl, and version (2 pickle files and a folder)
• PyTorch v1.3: ZIP file containing data.pkl (1 pickle file)
• PyTorch model archive format: ZIP file that includes Python code files and pickle files

Officially, PyTorch v0.1.1 and TorchScript < v1.4 are deprecated.
However, they are still supported by some legacy parsers

This description draws from this PyTorch GitHub issue: https://github.com/pytorch/pytorch/issues/31877.
If any inaccuracies in that description are found, that should be reflected in this code.
If any new PyTorch file formats are made, that should be added to this code.
Another useful reference is https://github.com/lutzroeder/netron/blob/main/source/pytorch.js.
"""


def check_zip_for_file(zip_path, file_name_or_extension, extension=False):
    # Many of the PyTorch file formats rely on ZIP
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


def check_pickle(file):
    # This only checks if the input is pickle-able. It is not a robust verificatication.
    try:
        Pickled.load(file)
        return True
    except Exception:  # noqa
        try:
            StackedPickle.load(file)
            return True
        except Exception:  # noqa
            return False


def find_file_properties(file, print_properties=False):
    # We separate format identification and properties to allow for more granular analysis
    properties = {}
    with open(file, "rb") as file:
        # PyTorch's torch.load() enforces a specific magic number at offset 0 for ZIP
        is_torch_zip = _is_zipfile(file)
        properties["is_torch_zip"] = is_torch_zip

        # This tarfile check has many false positivies. It is not a determinant of PyTorch v0.1.1.
        is_tar = tarfile.is_tarfile(file)
        properties["is_tar"] = is_tar

        # Similar to tar, this is not a robust verification.
        is_valid_pickle = check_pickle(file)
        properties["is_valid_pickle"] = is_valid_pickle

        # PyTorch MAR can be a standard ZIP, but not a PyTorch ZIP
        # Other non-PyTorch file formats rely on ZIP without PyTorch's limitations
        is_standard_zip = zipfile.is_zipfile(file)
        properties["is_standard_zip"] = is_standard_zip

        is_standard_not_torch = is_standard_zip and not is_torch_zip
        properties["is_standard_not_torch"] = is_standard_not_torch

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
                f"has_{'_'.join(f.split('.'))}": check_zip_for_file(file, f)
                for f in torch_zip_checks
            }
        properties.update(torch_zip_results)
    if print_properties:
        print("\nproperties:", properties, "\n")
    return properties


def check_if_legacy_format(file):
    required_entries = {"pickle", "storages", "tensors"}
    found_entries = set()
    try:
        with tarfile.open(file, mode="r:", format=tarfile.PAX_FORMAT) as tar:
            for member in iter(tar.next, None):
                found_entries.add(member.name)
                if required_entries.issubset(found_entries):
                    return True
    except Exception:  # noqa
        return False


def check_if_model_archive_format(file, properties):
    """
    References for the PyTorch Model Archive Format:
    1. https://pytorch.org/serve/getting_started.html
    2. https://github.com/pytorch/serve/tree/master/model-archiver
    """
    if properties["is_standard_zip"]:
        has_json = check_zip_for_file(file, ".json")
        has_serialized_model = check_zip_for_file(file, ".pt") or check_zip_for_file(file, ".pth")
        has_code = check_zip_for_file(file, ".py")
        if has_json and has_serialized_model and has_code:
            return True
        else:
            return False


def check_for_corruption(properties):
    # This can eventually be expanded to more cases
    corrupted = False
    reason = ""
    if properties["is_torch_zip"]:
        if (
            properties["has_model_json"]
            and not properties["has_attribute_pkl"]
            and not properties["has_constants_pkl"]
        ):
            corrupted = True
            reason = """Your file may be corrupted. It contained a
            model.json file without an attributes.pkl or constants.pkl file."""
    return corrupted, reason


def identify_pytorch_file_format(file, print_properties=False):
    # We are intentionally matching the semantics of the PyTorch reference parsers
    # To be polyglot-aware, we show the file formats ranked by likelihood
    properties = find_file_properties(file, print_properties)
    formats = []
    corrupted = False

    if properties["is_torch_zip"]:
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
            if all(properties[key] for key in keys)
        ]
    if properties["is_valid_pickle"]:
        formats.append("PyTorch v0.1.10")
    if properties["is_tar"]:
        is_pytorch_legacy_format = check_if_legacy_format(file)
        if is_pytorch_legacy_format:
            formats.append("PyTorch v0.1.1")
    if properties["is_standard_zip"]:
        is_model_archive_format = check_if_model_archive_format(file, properties)
        if is_model_archive_format:
            formats.append("PyTorch model archive format")
    corrupted, reason = check_for_corruption(properties)
    # Show results to user
    if corrupted:
        print(reason)
    if len(formats) != 0:
        primary = formats[0]
        print("Your file is most likely: ", primary, "\n")
        secondary = formats[1:]
        if len(secondary) != 0:
            print("The following file formats may also be valid: ", secondary)
    else:
        print("Your file may not be a PyTorch file. No valid file formats were detected.")
    return formats

def append_file(source_filename, destination_filename):
    # Open the source file in binary read mode
    with open(source_filename, 'rb') as source_file:
        content = source_file.read()

    # Open the destination file in binary append mode and write the content
    with open(destination_filename, 'ab') as destination_file:
        destination_file.write(content)
    return 

def make_zip_pickle_polyglot(zip_file, pickle_file):
    # MAR/PyTorch v0.1.10
    append_file(zip_file, pickle_file)
    return 

def identify_potential_polyglots(file, formats=None):
    if formats is None:
        formats = identify_pytorch_file_format(file)
    if "PyTorch model archive format" in formats:
        print("""
              PyTorch model archive format (MAR) found:
              Use fickling.polyglot.make_zip_pickle_polyglot(zip_file, pickle_file).
              This appends the MAR file to a pickle file. 
              You can create MAR/PyTorch v0.1.10 polyglots. 
              """)
    pass


zip_file = 'densenet161.mar'
pickle_file = 'legacy_model.pth'

make_zip_pickle_polyglot(zip_file, pickle_file)

torch.load(pickle_file)