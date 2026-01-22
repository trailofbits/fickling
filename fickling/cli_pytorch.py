"""CLI handlers for PyTorch model operations."""

from __future__ import annotations

import json
import sys
from ast import unparse
from pathlib import Path

from .analysis import Severity, check_safety
from .cli import DEFAULT_JSON_OUTPUT_FILE
from .fickle import Interpreter
from .tracing import Trace


def _check_torch_available() -> bool:
    """Check if PyTorch is available and provide helpful error message if not."""
    try:
        import torch  # noqa: F401

        return True
    except ImportError:
        sys.stderr.write(
            "Error: PyTorch is required for this command.\n"
            "Please install it with: pip install fickling[torch]\n"
        )
        return False


def handle_pytorch_command(args) -> int:
    """Handle the pytorch subcommand and its sub-subcommands."""
    if args.pytorch_command is None:
        sys.stderr.write("Error: pytorch subcommand required.\n")
        sys.stderr.write("Available commands: identify, show, check-safety, inject\n")
        sys.stderr.write("Use 'fickling pytorch --help' for more information.\n")
        return 1

    if args.pytorch_command == "identify":
        return _handle_pytorch_identify(args)
    if args.pytorch_command == "show":
        return _handle_pytorch_show(args)
    if args.pytorch_command == "check-safety":
        return _handle_pytorch_check_safety(args)
    if args.pytorch_command == "inject":
        return _handle_pytorch_inject(args)
    sys.stderr.write(f"Error: unknown pytorch command '{args.pytorch_command}'\n")
    return 1


def _handle_pytorch_identify(args) -> int:
    """Handle 'fickling pytorch identify FILE'."""
    if not _check_torch_available():
        return 1

    from .pytorch import PyTorchModelWrapper

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    try:
        wrapper = PyTorchModelWrapper(file_path, force=True)
        formats = wrapper.validate_file_format()

        formats_list = list(formats)
        if hasattr(args, "json") and args.json:
            result = {
                "file": str(file_path),
                "formats": formats_list,
                "primary_format": formats_list[0] if formats_list else None,
            }
            print(json.dumps(result, indent=2))
        else:
            if formats_list:
                print(f"Detected format(s) for {args.file}:")
                for i, fmt in enumerate(formats_list):
                    prefix = "  [primary]" if i == 0 else "  [also]   "
                    print(f"{prefix} {fmt}")
            else:
                print(f"No PyTorch formats detected for {args.file}")

        return 0
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error identifying file: {e}\n")
        return 1


def _handle_pytorch_show(args) -> int:
    """Handle 'fickling pytorch show FILE'."""
    if not _check_torch_available():
        return 1

    from .pytorch import PyTorchModelWrapper

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    force = getattr(args, "force", False)

    try:
        wrapper = PyTorchModelWrapper(file_path, force=force)
        pickled = wrapper.pickled

        interpreter = Interpreter(pickled)
        if getattr(args, "trace", False):
            trace = Trace(interpreter)
            print(unparse(trace.run()))
        else:
            print(unparse(interpreter.to_ast()))

        return 0
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.stderr.write("Use --force to attempt processing anyway.\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error reading PyTorch model: {e}\n")
        return 1


def _handle_pytorch_check_safety(args) -> int:
    """Handle 'fickling pytorch check-safety FILE'."""
    if not _check_torch_available():
        return 1

    from .pytorch import PyTorchModelWrapper

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    force = getattr(args, "force", False)
    json_output_path = getattr(args, "json_output", None) or DEFAULT_JSON_OUTPUT_FILE
    print_results = getattr(args, "print_results", False)

    try:
        wrapper = PyTorchModelWrapper(file_path, force=force)
        pickled = wrapper.pickled

        safety_results = check_safety(pickled, json_output_path=json_output_path)

        if print_results:
            print(safety_results.to_string())

        if safety_results.severity > Severity.LIKELY_SAFE:
            if print_results:
                sys.stderr.write(
                    "Warning: Fickling detected that the PyTorch model may be unsafe.\n\n"
                    "Do not load this model if it is from an untrusted source!\n\n"
                )
            return 1
        return 0
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.stderr.write("Use --force to attempt processing anyway.\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error checking PyTorch model safety: {e}\n")
        return 1


def _handle_pytorch_inject(args) -> int:
    """Handle 'fickling pytorch inject FILE -o OUTPUT -c CODE'."""
    if not _check_torch_available():
        return 1

    from .pytorch import PyTorchModelWrapper

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    output_path = Path(args.output)
    if output_path.exists() and not getattr(args, "overwrite", False):
        sys.stderr.write(f"Error: output file already exists: {args.output}\n")
        sys.stderr.write("Use --overwrite to replace the original file.\n")
        return 1

    force = getattr(args, "force", False)
    method = getattr(args, "method", "insertion")
    overwrite = getattr(args, "overwrite", False)
    code = args.code

    try:
        wrapper = PyTorchModelWrapper(file_path, force=force)
        wrapper.inject_payload(code, output_path, injection=method, overwrite=overwrite)
        print(f"Payload injected successfully. Output written to: {output_path}")
        return 0
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.stderr.write("Use --force to attempt processing anyway.\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error injecting payload: {e}\n")
        return 1
