import functools
import pickle
import warnings
from io import BytesIO
from pathlib import Path
from contextlib import contextmanager

import torch
import torch.utils._device
from torch.distributed.fsdp import FullStateDictConfig
from torch.distributed.fsdp import FullyShardedDataParallel as FSDP
from torch.distributed.fsdp import StateDictType
from torch.serialization import normalize_storage_type
from fickling.fickle import Pickled
"""
class SavingProxyForStorage:
    def __init__(self, obj, saver, protocol_version=5):
        self.protocol_version = protocol_version
        self.saver = saver
        if not (isinstance(obj, torch.storage.TypedStorage) or torch.is_storage(obj)):
            raise TypeError(f"expected storage, not {type(obj)}")

        # this logic is taken from PyTorch 2.0+ torch/serialization.py
        if isinstance(obj, torch.storage.TypedStorage):
            # PT upstream wants to deprecate this eventually...
            storage = obj._untyped_storage
            storage_type_str = obj._pickle_storage_type()
            storage_type = getattr(torch, storage_type_str)
            storage_numel = obj._size()
        else:
            storage = obj
            storage_type = normalize_storage_type(type(obj))
            storage_numel = storage.nbytes()

        storage_key = saver._write_storage_and_return_key(storage)
        location = torch.serialization.location_tag(storage)

        self.storage_info = (
            "storage",
            storage_type,
            storage_key,
            location,
            storage_numel,
        )

    def __reduce_ex__(self, protocol_version):
        assert False, "this should be handled with out of band"


class SavingProxyForTensor:
    def __init__(self, tensor, saver, protocol_version=5):
        self.protocol_version = protocol_version
        self.reduce_ret_fn, (storage, *other_reduce_args) = tensor.__reduce_ex__(
            protocol_version
        )
        assert isinstance(
            storage, torch.storage.TypedStorage
        ), "Please check for updates"
        storage_proxy = SavingProxyForStorage(
            storage, saver, protocol_version=protocol_version
        )
        self.reduce_args = (storage_proxy, *other_reduce_args)

    def __reduce_ex__(self, protocol_version):
        if protocol_version != self.protocol_version:
            raise RuntimeError(
                f"Unexpected protocol version: expected {self.protocol_version}, got {protocol_version}"
            )
        return self.reduce_ret_fn, self.reduce_args


class IncrementalPyTorchPickler(Pickled):
    def __init__(self, saver, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.storage_dtypes = {}
        self.saver = saver
        self.id_map = {}

    # this logic is taken from PyTorch 2.0+ torch/serialization.py
    def persistent_id(self, obj):
        # FIXME: the docs say that persistent_id should only return a string
        # but torch store returns tuples. This works only in the binary protocol
        # see
        # https://docs.python.org/2/library/pickle.html#pickling-and-unpickling-external-objects
        # https://github.com/python/cpython/blob/master/Lib/pickle.py#L527-L537
        if isinstance(obj, SavingProxyForStorage):
            return obj.storage_info

        if isinstance(obj, torch.storage.TypedStorage) or torch.is_storage(obj):
            if isinstance(obj, torch.storage.TypedStorage):
                # TODO: Once we decide to break serialization FC, this case
                # can be deleted
                storage = obj._untyped_storage
                storage_dtype = obj.dtype
                storage_type_str = obj._pickle_storage_type()
                storage_type = getattr(torch, storage_type_str)
                storage_numel = obj._size()

            else:
                storage = obj
                storage_dtype = torch.uint8
                storage_type = normalize_storage_type(type(obj))
                storage_numel = storage.nbytes()

            # If storage is allocated, ensure that any other saved storages
            # pointing to the same data all have the same dtype. If storage is
            # not allocated, don't perform this check
            if storage.data_ptr() != 0:
                if storage.data_ptr() in self.storage_dtypes:
                    if storage_dtype != self.storage_dtypes[storage.data_ptr()]:
                        raise RuntimeError(
                            "Cannot save multiple tensors or storages that "
                            "view the same data as different types"
                        )
                else:
                    self.storage_dtypes[storage.data_ptr()] = storage_dtype

            storage_key = self.id_map.get(storage._cdata)
            if storage_key is None:
                storage_key = self.saver._write_storage_and_return_key(storage)
                self.id_map[storage._cdata] = storage_key
            location = torch.serialization.location_tag(storage)

            return ("storage", storage_type, storage_key, location, storage_numel)

        return None
    
    def save(self, obj):
        # Inject the payload into the pickling process
        self.insert_python_exec(payload)
        super().save(obj)



# Use the custom pickler in the incremental_save class

class incremental_save:
    def __init__(self, name):
        self.name = name
        self.zipfile = torch._C.PyTorchFileWriter(str(name))
        self.has_saved = False
        self.next_key = 0

    def __enter__(self):
        return self

    def store_early(self, tensor):
        if isinstance(tensor, torch.Tensor):
            return SavingProxyForTensor(tensor, self)
        raise TypeError(f"can only store tensors early, not {type(tensor)}")


    def save(self, obj):
        if self.has_saved:
            raise RuntimeError("have already saved")
        # Write the pickle data for `obj`
        data_buf = BytesIO()
        pickler = IncrementalPyTorchPickler(self, data_buf) #, protocol=5)
        
        # Inject the payload into the pickling process
        #pickler.dispatch_table = {torch.Tensor: lambda pickler, obj: pickler.save_reduce(torch.Tensor, (obj.tolist(),), state=payload)}
        
        pickler.dump(obj)
        data_value = data_buf.getvalue()
        self.zipfile.write_record("data.pkl", data_value, len(data_value))
        self.has_saved = True

    def _write_storage_and_return_key(self, storage):
        if self.has_saved:
            raise RuntimeError("have already saved")
        key = self.next_key
        self.next_key += 1
        name = f"data/{key}"
        if storage.device.type != "cpu":
            storage = storage.cpu()
        num_bytes = storage.nbytes()
        self.zipfile.write_record(name, storage.data_ptr(), num_bytes)
        return key

    def __exit__(self, type, value, traceback):
        self.zipfile.write_end_of_file()


x = torch.tensor([0, 1, 2, 3, 4])
#payload = '''print("Injected Payload!")'''

#with incremental_save('tensor.pt') as saver:
#    saver.save(x)
"""
x = torch.tensor([0, 1, 2, 3, 4])
torch.save(x, 'tensor.pt')

# This function is from https://github.com/pytorch/pytorch/blob/main/torch/serialization.py
def _is_zipfile(f) -> bool:
    # This is a stricter implementation than zipfile.is_zipfile().
    # zipfile.is_zipfile() is True if the magic number appears anywhere in the
    # binary. Since we expect the files here to be generated by torch.save or
    # torch.jit.save, it's safe to only check the start bytes and avoid
    # collisions and assume the zip has only 1 file.
    # See bugs.python.org/issue28494.

    start = f.tell()
    # Read the first few bytes and match against the ZIP file signature
    local_header_magic_number = b'PK\x03\x04'
    read_bytes = f.read(len(local_header_magic_number))
    f.seek(start)
    return read_bytes == local_header_magic_number

def pytorch_format_detector(path: Path):
    # The PyTorch file format versions are drawn from here: https://github.com/pytorch/pytorch/issues/31877
    # Open a file and see if it is a zip file using _is_zipfile
    with open(path, 'rb') as f:
        is_tar_file = tarfile.is_tarfile(f.name)
        if _is_zipfile(f) == True: 
            is_zip_file = True
            with zipfile.ZipFile(f, 'r') as zip_ref:
                has_model_json = "model.json" in zip_ref.namelist()
                has_constants_pkl = "constants.pkl" in zip_ref.namelist()
                has_attribute_pkl = "attribute.pkl" in zip_ref.namelist()
                has_version = "version" in zip_ref.namelist()
        return _is_zipfile(f)
        try: 
            Pickled.load(f)
            is_multi_pickle_file = True
        except:
            is_multi_pickle_file = False

    #return (is_zip_file, is_tar_file, is_multi_pickle_file, has_model_json, has_constants_pkl, has_attribute_pkl, has_version)

print(pytorch_format_detector('tensor.pt'))
