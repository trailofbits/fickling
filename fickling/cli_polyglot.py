"""CLI handlers for polyglot detection and creation operations."""

from __future__ import annotations

import json
import sys
from pathlib import Path


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


def handle_polyglot_command(args) -> int:
    """Handle the polyglot subcommand and its sub-subcommands."""
    if args.polyglot_command is None:
        sys.stderr.write("Error: polyglot subcommand required.\n")
        sys.stderr.write("Available commands: identify, properties, create\n")
        sys.stderr.write("Use 'fickling polyglot --help' for more information.\n")
        return 1

    if args.polyglot_command == "identify":
        return _handle_polyglot_identify(args)
    if args.polyglot_command == "properties":
        return _handle_polyglot_properties(args)
    if args.polyglot_command == "create":
        return _handle_polyglot_create(args)
    sys.stderr.write(f"Error: unknown polyglot command '{args.polyglot_command}'\n")
    return 1


def _handle_polyglot_identify(args) -> int:
    """Handle 'fickling polyglot identify FILE'."""
    if not _check_torch_available():
        return 1

    from .polyglot import identify_pytorch_file_format

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    try:
        formats = identify_pytorch_file_format(args.file, print_results=False)

        if hasattr(args, "json") and args.json:
            result = {
                "file": str(file_path),
                "formats": formats,
                "primary_format": formats[0] if formats else None,
                "is_polyglot": len(formats) > 1,
            }
            print(json.dumps(result, indent=2))
        else:
            if formats:
                print(f"Identified format(s) for {args.file}:")
                for i, fmt in enumerate(formats):
                    prefix = "  [primary]" if i == 0 else "  [also]   "
                    print(f"{prefix} {fmt}")
                if len(formats) > 1:
                    print("\n  Note: Multiple formats detected - this may be a polyglot file.")
            else:
                print(f"No PyTorch formats detected for {args.file}")
                print("This file may not be a PyTorch file, or it may be in an unsupported format.")

        return 0
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error identifying file: {e}\n")
        return 1


def _handle_polyglot_properties(args) -> int:
    """Handle 'fickling polyglot properties FILE'."""
    if not _check_torch_available():
        return 1

    from .polyglot import find_file_properties, find_file_properties_recursively

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    recursive = getattr(args, "recursive", False)

    try:
        if recursive:
            properties = find_file_properties_recursively(args.file, print_properties=False)
        else:
            properties = find_file_properties(args.file, print_properties=False)

        if hasattr(args, "json") and args.json:
            result = {
                "file": str(file_path),
                "properties": properties,
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"File properties for {args.file}:")
            _print_properties(properties, indent=2)

        return 0
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error analyzing file properties: {e}\n")
        return 1


def _print_properties(properties: dict, indent: int = 0) -> None:
    """Pretty-print file properties."""
    prefix = " " * indent
    for key, value in properties.items():
        if key == "children" and isinstance(value, dict):
            print(f"{prefix}{key}:")
            for child_name, child_props in value.items():
                print(f"{prefix}  {child_name}:")
                if child_props is not None:
                    _print_properties(child_props, indent + 4)
                else:
                    print(f"{prefix}    (unable to read)")
        else:
            print(f"{prefix}{key}: {value}")


def _handle_polyglot_create(args) -> int:
    """Handle 'fickling polyglot create FILE1 FILE2 -o OUTPUT'."""
    if not _check_torch_available():
        return 1

    from .polyglot import create_polyglot

    file1_path = Path(args.file1)
    file2_path = Path(args.file2)

    if not file1_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file1}\n")
        return 1
    if not file2_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file2}\n")
        return 1

    output_path = getattr(args, "output", None)
    quiet = getattr(args, "quiet", False)

    try:
        success = create_polyglot(
            args.file1, args.file2, polyglot_file_name=output_path, print_results=not quiet
        )

        if success:
            return 0
        if not quiet:
            sys.stderr.write("Failed to create polyglot. The file formats may not be compatible.\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error creating polyglot: {e}\n")
        return 1
