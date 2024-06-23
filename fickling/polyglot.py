import ast
import os
import shutil
import struct
import sys
import tarfile
import tempfile
import zipfile

import numpy.lib.format as npformat

from fickling.fickle import Pickled, StackedPickle

"""
PyTorch file format identification:

We currently support the following PyTorch file formats:
• PyTorch v0.1.1: Tar file with sys_info, pickle, storages, and tensors
• PyTorch v0.1.10: Stacked pickle files
• TorchScript v1.0: ZIP file with model.json
• TorchScript v1.1: ZIP file with model.json and attributes.pkl (a JSON file and a pickle file)
• TorchScript v1.3: ZIP file with data.pkl and constants.pkl (2 pickle files)
• TorchScript v1.4: ZIP file with data.pkl, constants.pkl, and version set at 2 or higher
• PyTorch v1.3: ZIP file containing data.pkl (1 pickle file)
• PyTorch model archive format[ZIP]: ZIP file that includes Python code files and pickle files

This description draws from this PyTorch GitHub issue: https://github.com/pytorch/pytorch/issues/31877.
If any inaccuracies in that description are found, that should be reflected in this code.
If any new PyTorch file formats are made, that should be added to this code.
Another useful reference is https://github.com/lutzroeder/netron/blob/main/source/pytorch.js.
"""

try:
    from torch.serialization import _is_zipfile
except ModuleNotFoundError:
    raise ImportError(
        "The 'torch' module is required for this functionality."
        "PyTorch is now an optional dependency in Fickling."
        "Please use `pip install fickling[torch]`"
    )


def check_and_find_in_zip(
    zip_path, file_name_or_extension, return_path=False, check_extension=False
):
    """Check for a file in the zip and return its path or boolean if found."""
    try:
        if not (return_path):
            with zipfile.ZipFile(zip_path, "r") as zip_file:
                if check_extension:
                    return any(
                        entry.endswith(file_name_or_extension) for entry in zip_file.namelist()
                    )
                else:
                    return any(file_name_or_extension in entry for entry in zip_file.namelist())
        else:
            return next(
                (entry for entry in zip_path.namelist() if entry.endswith(file_name_or_extension)),
                None,
            )
    except zipfile.BadZipFile:
        print(f"Invalid ZIP file: {zip_path}")
        return None if return_path else False
    except FileNotFoundError:
        print(f"File not found: {zip_path}")
        return None if return_path else False


def check_numpy(file):  # returns isNumpy,isNumpyPickle
    """Checks if the numpy magic bytes are there, and if they are, if the header
    claims the data is an object"""
    file.seek(0)
    try:
        version = npformat.read_magic(file)
    except ValueError:
        return False, False  # not numpy

    # This is a private variable, but the alternative
    # would require using private functions or
    # maintaining Numpy's version list in Fickling
    hinfo = npformat._header_size_info.get(version)
    if hinfo is None:
        return False, False  # not a valid version of numpy
    hlength_type, encoding = hinfo

    hlength_str = file.read(struct.calcsize(hlength_type))
    header_length = struct.unpack(hlength_type, hlength_str)[0]
    header = file.read(header_length)
    header = header.decode(encoding)

    # The literal_eval can be abused to cause a DoS
    # However this is also what Numpy uses,
    # so it applies to np.load(fname, allow_pickle=False)
    d = ast.literal_eval(header)
    dtype = npformat.descr_to_dtype(d["descr"])

    if dtype.hasobject:
        return True, True  # numpy pickle
    return True, False  # numpy non-pickle


def check_pickle(file, min_length=0):
    """Checks if a file can be pickled; this does not directly determine the file is a pickle"""
    try:
        opcodes = Pickled.load(file).opcodes()
        return len(opcodes) > min_length
    except Exception:  # noqa
        try:
            StackedPickle.load(file)
            return True
        except Exception:  # noqa
            return False


def find_file_properties(file_path, print_properties=False):
    """For a more granular analysis, we separate property discovery and format identification"""
    properties = {}
    with open(file_path, "rb") as file:
        # PyTorch's torch.load() enforces a specific magic number at offset 0 for ZIP
        is_torch_zip = _is_zipfile(file)
        properties["is_torch_zip"] = is_torch_zip

        # This tarfile check has many false positives. It is not a determinant of PyTorch v0.1.1.
        if sys.version_info >= (3, 9):
            is_tar = tarfile.is_tarfile(file)
        else:
            is_tar = tarfile.is_tarfile(file_path)
        properties["is_tar"] = is_tar

        # Similar to tar, this is not a robust verification.
        # tar files often start with . which is a 1 operator pickle
        is_valid_pickle = check_pickle(file, min_length=2)
        properties["is_valid_pickle"] = is_valid_pickle

        # Numpy has a special header and magic bytes,
        # mimics Numpy code to check if the file is Numpy
        # and if it claims to contain a pickle
        is_numpy, is_numpy_pickle = check_numpy(file)
        properties["is_numpy"] = is_numpy
        properties["is_numpy_pickle"] = is_numpy_pickle

        # PyTorch MAR can be a standard ZIP, but not a PyTorch ZIP
        # Some other non-PyTorch file formats rely on ZIP without PyTorch's limitations
        is_standard_zip = zipfile.is_zipfile(file)
        properties["is_standard_zip"] = is_standard_zip

        is_standard_not_torch = is_standard_zip and not is_torch_zip
        properties["is_standard_not_torch"] = is_standard_not_torch

        torch_zip_results = {
            "has_constants_pkl": False,
            "has_data_pkl": False,
            "has_version": False,
            "has_model_json": False,
            "has_attributes_pkl": False,
        }
        if is_torch_zip:
            torch_zip_checks = [
                "data.pkl",
                "constants.pkl",
                "version",
                "model.json",
                "attributes.pkl",
            ]
            torch_zip_results = {
                f"has_{'_'.join(f.split('.'))}": check_and_find_in_zip(
                    file, f, check_extension=False
                )
                for f in torch_zip_checks
            }
        properties.update(torch_zip_results)
    if print_properties:
        print("\nproperties:", properties, "\n")
    return properties


def find_file_properties_recursively(file_path, print_properties=False):
    """Property discovery that looks inside zip and tar archives"""
    properties = find_file_properties(file_path, print_properties)

    # check zip
    check_zip = properties["is_standard_zip"]
    # if it's the correct type of zip to be torch, make sure it's not a torch file
    if check_zip and not properties["is_standard_not_torch"]:
        for key in properties.keys():
            if key.startswith("has_") and properties[key]:
                # if it is a torch file, no need to check it
                check_zip = False
                break
    # actually check the zip
    if check_zip:
        properties["children"] = {}
        with tempfile.TemporaryDirectory() as tempdir:
            with zipfile.ZipFile(file_path) as zipped_file:
                for fname in zipped_file.namelist():
                    zipped_file.extract(fname, path=tempdir)
                    fname_path = os.path.join(tempdir, fname)
                    properties["children"][fname] = find_file_properties_recursively(
                        fname_path, print_properties
                    )

    # check tar
    if properties["is_tar"]:  # tar archive
        properties["children"] = {}
        with tempfile.TemporaryDirectory() as tempdir:
            with tarfile.TarFile(file_path) as tarred_file:
                for fname in tarred_file.getnames():
                    content = tarred_file.extractfile(fname)
                    if content is None:
                        properties["children"][fname] = None
                        continue
                    fname_path = os.path.join(tempdir, os.path.basename(fname))
                    open(fname_path, "wb").write(content.read())
                    properties["children"][fname] = find_file_properties_recursively(
                        fname_path, print_properties
                    )

    return properties


def check_if_legacy_format(file):
    """PyTorch v0.1.1: Tar file with sys_info, pickle, storages, and tensors"""
    required_entries = {"pickle", "storages", "tensors"}
    found_entries = set()
    print("check_if_legacy_format")
    try:
        with tarfile.open(file, mode="r:", format=tarfile.PAX_FORMAT) as tar:
            for member in iter(tar.next, None):
                found_entries.add(member.name)
                if required_entries.issubset(found_entries):
                    print("True")
                    return True
    except Exception:  # noqa
        print("False")
        return False


def check_if_model_archive_format(file, properties):
    """
    PyTorch model archive format: ZIP file that includes Python code files and pickle files

    References for the PyTorch Model Archive Format:
    1. https://pytorch.org/serve/getting_started.html
    2. https://github.com/pytorch/serve/tree/master/model-archiver
    """
    if properties["is_standard_zip"]:
        has_json = check_and_find_in_zip(file, ".json", check_extension=True)
        has_serialized_model = check_and_find_in_zip(
            file, ".pt", check_extension=True
        ) or check_and_find_in_zip(file, ".pth", check_extension=True)
        has_code = check_and_find_in_zip(file, ".py", check_extension=True)
        return has_json and has_serialized_model and has_code


def check_for_corruption(properties):
    """Checks for corruption at the PyTorch file format level"""
    corrupted = False
    reason = ""
    # We expect this to be expanded upon
    if properties["is_torch_zip"]:
        if (
            properties["has_model_json"]
            and not properties["has_attributes_pkl"]
            and not properties["has_constants_pkl"]
        ):
            corrupted = True
            reason = """Your file may be corrupted. It contained a
            model.json file without an attributes.pkl or constants.pkl file."""
    return corrupted, reason


def identify_pytorch_file_format(file, print_properties=False, print_results=False):
    """
    We are intentionally matching the semantics of the PyTorch reference parsers.
    To be polyglot-aware, we show the file formats ranked by likelihood.
    Our parsing depth is at the file structure level;
    However, it can be at the full parsing level if necessary.
    """
    properties = find_file_properties(file, print_properties)
    formats = []
    corrupted = False
    # The order of this identification is intentional and tries to match PyTorch
    if properties["is_torch_zip"]:
        format_conditions = [
            (["has_data_pkl", "has_constants_pkl", "has_version"], "TorchScript v1.4"),
            (["has_data_pkl", "has_constants_pkl"], "TorchScript v1.3"),
            (["has_model_json", "has_constants_pkl"], "TorchScript v1.0"),
            (["has_model_json", "has_attributes_pkl"], "TorchScript v1.1"),
            (["has_data_pkl"], "PyTorch v1.3"),
        ]
        formats = [
            format_name
            for keys, format_name in format_conditions
            if all(properties[key] for key in keys)
        ]

    if properties["is_tar"]:
        is_pytorch_legacy_format = check_if_legacy_format(file)
        if is_pytorch_legacy_format:
            formats.append("PyTorch v0.1.1")
    if properties["is_valid_pickle"]:
        formats.append("PyTorch v0.1.10")
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
        if print_results:
            print("Your file is most likely of this format: ", primary, "\n")
        secondary = formats[1:]
        if len(secondary) != 0:
            if print_results:
                print(
                    "It is also possible that your file can be validly interpreted as: ", secondary
                )
    else:
        if print_results:
            print(
                """Your file may not be a PyTorch file.
                No valid file formats were detected.
                If this is a mistake, raise an issue on our GitHub."""
            )
    return formats


def append_file(source_filename, destination_filename):
    with open(source_filename, "rb") as source_file:
        content = source_file.read()
    with open(destination_filename, "ab") as destination_file:
        destination_file.write(content)
    return destination_filename


def create_zip_pickle_polyglot(zip_file, pickle_file):
    append_file(zip_file, pickle_file)


def create_mar_legacy_pickle_polyglot(
    files, print_results=False, polyglot_file_name="polyglot.mar.pt"
):
    files.sort(key=lambda x: x[1] != "PyTorch model archive format")
    if print_results:
        print("Making a PyTorch MAR/PyTorch v0.1.10 polyglot")
    polyglot_file = append_file(*[file[0] for file in files])
    shutil.copy(polyglot_file, polyglot_file_name)
    polyglot_found = True
    return polyglot_found


def create_standard_torchscript_polyglot(
    files, print_results=False, polyglot_file_name="polyglot.pt"
):
    if print_results:
        print("Making a PyTorch v1.3/TorchScript v1.4 polyglot")
        print("Warning: For some parsers, this may generate polymocks instead of polyglots.")
    standard_pytorch_file = [file[0] for file in files if file[1] == "PyTorch v1.3"][0]
    torchscript_file = [file[0] for file in files if file[1] == "TorchScript v1.4"][0]
    if polyglot_file_name is None:
        polyglot_file_name = "polyglot.pt"
    shutil.copy(standard_pytorch_file, polyglot_file_name)

    with zipfile.ZipFile(torchscript_file, "r") as zip_b:
        constants_pkl_path = check_and_find_in_zip(
            zip_b, "constants.pkl", check_extension=False, return_path=True
        )
        version_path = check_and_find_in_zip(zip_b, "version", return_path=True)
        if constants_pkl_path and version_path:
            zip_b.extract(constants_pkl_path, "temp")
            zip_b.extract(version_path, "temp")

    with zipfile.ZipFile(polyglot_file_name, "a") as zip_out:
        zip_out.write(f"temp/{constants_pkl_path}", "constants.pkl")
        zip_out.write(f"temp/{version_path}", "version")

    shutil.rmtree("temp")
    polyglot_found = True
    return polyglot_found


def create_mar_legacy_tar_polyglot(
    files, print_results=False, polyglot_file_name="polyglot.mar.tar"
):
    if print_results:
        print("Making a PyTorch v0.1.1/PyTorch MAR polyglot")
    mar_file = [file[0] for file in files if file[1] == "PyTorch model archive format"][0]
    tar_file = [file[0] for file in files if file[1] == "PyTorch v0.1.1"][0]
    polyglot_file = append_file(mar_file, tar_file)
    shutil.copy(polyglot_file, polyglot_file_name)
    polyglot_found = True
    return polyglot_found


def create_polyglot(first_file, second_file, polyglot_file_name=None, print_results=True):
    polyglot_found = False
    temp_first_file = "temp_" + os.path.basename(first_file)
    temp_second_file = "temp_" + os.path.basename(second_file)
    shutil.copy(first_file, temp_first_file)
    shutil.copy(second_file, temp_second_file)
    files = [
        (temp_first_file, identify_pytorch_file_format(temp_first_file)[0]),
        (temp_second_file, identify_pytorch_file_format(temp_second_file)[0]),
    ]
    formats = set(map(lambda x: x[1], files))  # noqa
    if {"PyTorch model archive format", "PyTorch v0.1.10"}.issubset(formats):
        if polyglot_file_name is None:
            polyglot_file_name = "polyglot.mar.pt"
        polyglot_found = create_mar_legacy_pickle_polyglot(files, print_results, polyglot_file_name)
    if {"PyTorch v1.3", "TorchScript v1.4"}.issubset(formats):
        if polyglot_file_name is None:
            polyglot_file_name = "polyglot.pt"
        polyglot_found = create_standard_torchscript_polyglot(
            files, print_results, polyglot_file_name
        )
    if {"PyTorch model archive format", "PyTorch v0.1.1"}.issubset(formats):
        if polyglot_file_name is None:
            polyglot_file_name = "polyglot.mar.tar"
        polyglot_found = create_mar_legacy_tar_polyglot(files, print_results, polyglot_file_name)
    if print_results:
        if polyglot_found is False:
            print(
                """Fickling was not able to create any polyglots.
                  If you think this is a mistake, raise an issue on our GitHub."""
            )
        else:
            print(f"The polyglot is contained in {polyglot_file_name}")
    os.remove(temp_first_file)
    os.remove(temp_second_file)
    return polyglot_found
