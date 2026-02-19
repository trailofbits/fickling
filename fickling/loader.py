from __future__ import annotations

import pickle
from io import BytesIO
from pathlib import Path

from fickling.analysis import Severity, check_safety
from fickling.exception import UnsafeFileError
from fickling.fickle import Pickled, StackedPickle


def load(
    file,
    max_acceptable_severity=Severity.LIKELY_SAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.load()"""
    pickled_data = Pickled.load(file, fail_on_decode_error=False)
    result = check_safety(pickled=pickled_data, json_output_path=json_output_path)
    if result.severity <= max_acceptable_severity and not pickled_data.has_invalid_opcode:
        # We don't do pickle.load(file) because it could allow for a race
        # condition where the file we check is not the same that gets
        # loaded after the analysis.
        return pickle.loads(pickled_data.dumps(), *args, **kwargs)
    if pickled_data.has_invalid_opcode:
        raise UnsafeFileError(
            file,
            "This file contains an invalid opcode sequence. It is "
            "either corrupted or maliciously attempting to bypass "
            "pickle analysis tools",
        )
    raise UnsafeFileError(file, result.to_dict())


def loads(
    data,
    max_acceptable_severity=Severity.LIKELY_SAFE,
    print_results=False,
    json_output_path=None,
    *args,
    **kwargs,
):
    """Exposed as fickling.loads()

    Safely loads a pickle from bytes data after performing security analysis.

    Args:
        data: Bytes data containing the pickled object
        max_acceptable_severity: Maximum acceptable severity level (default: LIKELY_SAFE)
        print_results: Whether to print analysis results (default: False)
        json_output_path: Optional path to write JSON analysis results
        *args: Additional arguments passed to pickle.loads()
        **kwargs: Additional keyword arguments passed to pickle.loads()

    Returns:
        The unpickled object

    Raises:
        UnsafeFileError: If the pickle data is unsafe or contains invalid opcodes
    """
    # Convert bytes to file-like object
    file = BytesIO(data)

    # Reuse existing load() function which already handles all the logic
    return load(
        file,
        *args,
        max_acceptable_severity=max_acceptable_severity,
        print_results=print_results,
        json_output_path=json_output_path,
        **kwargs,
    )


def auto_load(path: Path | str) -> tuple[str, StackedPickle]:
    """
    Auto-detect file format and load the pickle content.

    This function automatically detects whether the file is a PyTorch model (ZIP format),
    a plain pickle, or other supported formats, and returns the appropriate Pickled data.

    Args:
        path: Path to the file to load

    Returns:
        A tuple of (format_name, pickled_data) where:
        - format_name: A string describing the detected format (e.g., "PyTorch v1.3", "pickle")
        - pickled_data: A StackedPickle containing one or more Pickled objects

    Raises:
        ValueError: If the file format cannot be determined or is unsupported
    """
    if isinstance(path, str):
        path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Try PyTorch ZIP formats first (most common for ML models)
    try:
        from fickling.polyglot import identify_pytorch_file_format

        formats = identify_pytorch_file_format(path, print_results=False)

        if formats:
            primary_format = formats[0]

            # Handle PyTorch v1.3 and TorchScript v1.4 (ZIP with data.pkl)
            if primary_format in ("PyTorch v1.3", "TorchScript v1.4", "TorchScript v1.3"):
                from fickling.pytorch import PyTorchModelWrapper

                wrapper = PyTorchModelWrapper(path, force=True)
                # Return as StackedPickle for consistency
                return primary_format, StackedPickle([wrapper.pickled])

            # Handle legacy formats as plain pickle
            if primary_format == "PyTorch v0.1.10":
                with open(path, "rb") as f:
                    stacked = StackedPickle.load(f, fail_on_decode_error=False)
                return primary_format, stacked

    except ImportError:
        # torch not installed, fall through to plain pickle handling
        pass

    # Fall back to plain pickle
    try:
        with open(path, "rb") as f:
            stacked = StackedPickle.load(f, fail_on_decode_error=False)
        return "pickle", stacked
    except Exception as e:
        raise ValueError(f"Unable to load file as pickle: {e}") from e
