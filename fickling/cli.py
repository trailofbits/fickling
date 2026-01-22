"""Fickling CLI - Pickle security analyzer with auto-detection."""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser
from ast import unparse
from pathlib import Path

from . import __version__, fickle, tracing
from .analysis import Severity, check_safety

DEFAULT_JSON_OUTPUT_FILE = "safety_results.json"

# Commands that use the new subcommand interface
COMMANDS = {"check", "inject", "info", "create-polyglot"}


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


def _create_legacy_parser() -> ArgumentParser:
    """Create parser for legacy CLI behavior (backward compatibility)."""
    parser = ArgumentParser(
        prog="fickling",
        description="Pickle security analyzer with auto-detection for PyTorch models",
    )
    parser.add_argument("--version", "-v", action="store_true", help="print version and exit")
    parser.add_argument(
        "file",
        type=str,
        nargs="?",
        default="-",
        help="file to analyze (default: stdin)",
    )
    parser.add_argument(
        "--check-safety",
        "-s",
        action="store_true",
        help="(legacy) run safety analysis - prefer 'fickling check FILE'",
    )
    parser.add_argument(
        "--inject",
        "-i",
        type=str,
        default=None,
        help="(legacy) inject code - prefer 'fickling inject FILE -c CODE -o OUT'",
    )
    parser.add_argument(
        "--inject-target",
        type=int,
        default=0,
        help="index of stacked pickle to inject into (default: 0)",
    )
    parser.add_argument(
        "--create",
        "-c",
        type=str,
        default=None,
        help="(legacy) create pickle from Python expression",
    )
    parser.add_argument(
        "--run-last",
        "-l",
        action="store_true",
        help="run injected code after existing code",
    )
    parser.add_argument(
        "--replace-result",
        "-r",
        action="store_true",
        help="replace unpickle result with injected code return value",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help=f"path to output JSON file (default: {DEFAULT_JSON_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--print-results",
        "-p",
        action="store_true",
        help="print analysis results to console",
    )
    parser.add_argument(
        "--trace",
        "-t",
        action="store_true",
        help="print a runtime trace while interpreting",
    )
    return parser


def _create_command_parser() -> ArgumentParser:
    """Create parser with subcommands for new flat command structure."""
    parser = ArgumentParser(
        prog="fickling",
        description="Pickle security analyzer with auto-detection for PyTorch models",
    )
    parser.add_argument("--version", "-v", action="store_true", help="print version and exit")

    subparsers = parser.add_subparsers(dest="command", help="available commands")

    # === check: Safety analysis ===
    check_parser = subparsers.add_parser(
        "check",
        help="safety check any pickle/model file",
        description="Run safety analysis on any pickle or PyTorch model file (auto-detects format)",
    )
    check_parser.add_argument("file", type=str, help="file to check")
    check_parser.add_argument("--json", action="store_true", help="output results as JSON")
    check_parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help=f"path to output JSON file (default: {DEFAULT_JSON_OUTPUT_FILE})",
    )
    check_parser.add_argument(
        "--print-results", "-p", action="store_true", help="print detailed results to console"
    )

    # === inject: Payload injection ===
    inject_parser = subparsers.add_parser(
        "inject",
        help="inject payload into pickle/model file",
        description="Inject Python code into a pickle or PyTorch model file (auto-detects format)",
    )
    inject_parser.add_argument("file", type=str, help="file to inject into")
    inject_parser.add_argument(
        "-c", "--code", type=str, required=True, help="Python code to inject"
    )
    inject_parser.add_argument("-o", "--output", type=str, required=True, help="output file path")
    inject_parser.add_argument(
        "--method",
        type=str,
        choices=["insertion", "combination"],
        default="insertion",
        help="injection method for PyTorch models (default: insertion)",
    )
    inject_parser.add_argument(
        "--run-last",
        "-l",
        action="store_true",
        help="run injected code after existing code (default: before)",
    )
    inject_parser.add_argument(
        "--replace-result",
        "-r",
        action="store_true",
        help="replace unpickle result with injected code return value",
    )
    inject_parser.add_argument(
        "--overwrite", action="store_true", help="overwrite output file if exists"
    )

    # === info: Format identification ===
    info_parser = subparsers.add_parser(
        "info",
        help="show format and properties of a file",
        description="Identify file format and show properties (requires PyTorch for full detection)",
    )
    info_parser.add_argument("file", type=str, help="file to analyze")
    info_parser.add_argument("--json", action="store_true", help="output results as JSON")
    info_parser.add_argument(
        "-r", "--recursive", action="store_true", help="analyze recursively into archives"
    )

    # === create-polyglot: Polyglot creation ===
    polyglot_parser = subparsers.add_parser(
        "create-polyglot",
        help="create a polyglot file from two inputs",
        description="Create a polyglot file by combining two PyTorch/pickle files",
    )
    polyglot_parser.add_argument("file1", type=str, help="first input file")
    polyglot_parser.add_argument("file2", type=str, help="second input file")
    polyglot_parser.add_argument("-o", "--output", type=str, default=None, help="output file path")
    polyglot_parser.add_argument(
        "--quiet", "-q", action="store_true", help="suppress output messages"
    )

    return parser


def _get_first_positional(argv: list[str]) -> str | None:
    """Get the first non-flag argument (potential command or file)."""
    for arg in argv[1:]:
        if not arg.startswith("-"):
            return arg
    return None


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv

    # Check for version flag first
    if "--version" in argv or "-v" in argv:
        if len(argv) == 2:  # Only version flag present
            if sys.stdout.isatty():
                print(f"fickling version {__version__}")
            else:
                print(__version__)
            return 0

    # Determine if we're using a new command or legacy CLI
    first_positional = _get_first_positional(argv)

    if first_positional in COMMANDS:
        # Use new command parser
        parser = _create_command_parser()
        args = parser.parse_args(argv[1:])

        if args.command == "check":
            return _handle_check(args)
        if args.command == "inject":
            return _handle_inject(args)
        if args.command == "info":
            return _handle_info(args)
        if args.command == "create-polyglot":
            return _handle_create_polyglot(args)
        return 1

    # Use legacy parser for backward compatibility
    parser = _create_legacy_parser()
    args = parser.parse_args(argv[1:])
    return _handle_legacy(args)


def _handle_check(args) -> int:
    """Handle 'fickling check FILE' - safety analysis with auto-detection."""
    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    json_output_path = args.json_output or DEFAULT_JSON_OUTPUT_FILE
    print_results = getattr(args, "print_results", False)

    try:
        from .loader import auto_load

        format_name, stacked_pickled = auto_load(file_path)

        if not getattr(args, "json", False):
            print(f"Detected format: {format_name}")

        was_safe = True
        all_results = []

        for pickled in stacked_pickled:
            safety_results = check_safety(pickled, json_output_path=json_output_path)
            all_results.append(safety_results)

            if safety_results.severity > Severity.LIKELY_SAFE:
                was_safe = False

        if getattr(args, "json", False):
            result = {
                "file": str(file_path),
                "format": format_name,
                "safe": was_safe,
                "severity": max(r.severity.value for r in all_results),
                "results": [r.to_dict() for r in all_results],
            }
            print(json.dumps(result, indent=2))
        else:
            if print_results:
                for i, safety_results in enumerate(all_results):
                    if len(all_results) > 1:
                        print(f"\n--- Pickle {i} ---")
                    print(safety_results.to_string())

            if was_safe:
                print("No unsafe operations detected.")
            else:
                sys.stderr.write(
                    "\nWarning: Potentially unsafe operations detected.\n"
                    "Do not unpickle this file if it is from an untrusted source!\n"
                )

        return 0 if was_safe else 1

    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except ValueError as e:
        sys.stderr.write(f"Error loading file: {e}\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error: {e}\n")
        return 1


def _handle_inject(args) -> int:
    """Handle 'fickling inject FILE -c CODE -o OUT' - payload injection with auto-detection."""
    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    output_path = Path(args.output)
    if output_path.exists() and not getattr(args, "overwrite", False):
        sys.stderr.write(f"Error: output file already exists: {args.output}\n")
        sys.stderr.write("Use --overwrite to replace it.\n")
        return 1

    try:
        from .loader import auto_load

        format_name, stacked_pickled = auto_load(file_path)
        print(f"Detected format: {format_name}")

        # For PyTorch ZIP formats, use PyTorchModelWrapper for proper injection
        if format_name in ("PyTorch v1.3", "TorchScript v1.4", "TorchScript v1.3"):
            if not _check_torch_available():
                return 1

            from .pytorch import PyTorchModelWrapper

            method = getattr(args, "method", "insertion")
            overwrite = getattr(args, "overwrite", False)

            wrapper = PyTorchModelWrapper(file_path, force=True)
            wrapper.inject_payload(args.code, output_path, injection=method, overwrite=overwrite)
            print(f"Payload injected successfully. Output: {output_path}")
            return 0

        # For plain pickle, use direct injection
        if args.output == "-":
            buffer = (
                sys.stdout.buffer
                if hasattr(sys.stdout, "buffer") and sys.stdout.buffer
                else sys.stdout
            )
            should_close = False
        else:
            buffer = open(output_path, "wb")
            should_close = True

        try:
            inject_target = getattr(args, "inject_target", 0)
            if inject_target >= len(stacked_pickled):
                inject_target = 0

            for pickled in stacked_pickled[:inject_target]:
                pickled.dump(buffer)

            pickled = stacked_pickled[inject_target]
            pickled.insert_python_eval(
                args.code,
                run_first=not getattr(args, "run_last", False),
                use_output_as_unpickle_result=getattr(args, "replace_result", False),
            )
            pickled.dump(buffer)

            for pickled in stacked_pickled[inject_target + 1 :]:
                pickled.dump(buffer)

            print(f"Payload injected successfully. Output: {output_path}")
            return 0
        finally:
            if should_close:
                buffer.close()

    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error injecting payload: {e}\n")
        return 1


def _handle_info(args) -> int:
    """Handle 'fickling info FILE' - format identification and properties."""
    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"Error: file not found: {args.file}\n")
        return 1

    # Try to use polyglot module for detailed analysis (requires torch)
    try:
        from .polyglot import (
            find_file_properties,
            find_file_properties_recursively,
            identify_pytorch_file_format,
        )

        formats = identify_pytorch_file_format(args.file, print_results=False)
        recursive = getattr(args, "recursive", False)

        if recursive:
            properties = find_file_properties_recursively(args.file, print_properties=False)
        else:
            properties = find_file_properties(args.file, print_properties=False)

        if getattr(args, "json", False):
            result = {
                "file": str(file_path),
                "formats": formats,
                "primary_format": formats[0] if formats else None,
                "is_polyglot": len(formats) > 1,
                "properties": properties,
            }
            print(json.dumps(result, indent=2))
        else:
            if formats:
                print(f"Format: {formats[0]}")
                if len(formats) > 1:
                    print(f"Also valid as: {', '.join(formats[1:])}")
                    print("(This file may be a polyglot)")
            else:
                print("Format: pickle (no specific PyTorch format detected)")

            print("\nProperties:")
            _print_properties(properties, indent=2)

        return 0

    except ImportError:
        # torch not installed - provide basic info
        try:
            with open(file_path, "rb") as f:
                stacked = fickle.StackedPickle.load(f, fail_on_decode_error=False)

            if getattr(args, "json", False):
                result = {
                    "file": str(file_path),
                    "formats": ["pickle"],
                    "primary_format": "pickle",
                    "is_polyglot": False,
                    "pickle_count": len(stacked),
                }
                print(json.dumps(result, indent=2))
            else:
                print("Format: pickle")
                print(f"Stacked pickles: {len(stacked)}")
                print("\nNote: Install PyTorch for detailed format detection:")
                print("  pip install fickling[torch]")

            return 0
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"Error reading file: {e}\n")
            return 1

    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error: {e}\n")
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


def _handle_create_polyglot(args) -> int:
    """Handle 'fickling create-polyglot FILE1 FILE2 -o OUT'."""
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


def _handle_legacy(args) -> int:
    """Handle legacy CLI behavior (backward compatibility)."""
    # Handle --check-safety flag
    if args.check_safety:
        if args.file and args.file != "-":
            # Create a fake args object for _handle_check
            class CheckArgs:
                pass

            check_args = CheckArgs()
            check_args.file = args.file
            check_args.json = False
            check_args.json_output = args.json_output
            check_args.print_results = args.print_results
            return _handle_check(check_args)
        sys.stderr.write("Error: file path required with --check-safety\n")
        return 1

    # Handle --inject flag
    if args.inject:
        # For legacy inject, output goes to stdout
        if args.file == "-":
            file = sys.stdin.buffer if hasattr(sys.stdin, "buffer") else sys.stdin
        else:
            file = open(args.file, "rb")

        try:
            stacked_pickled = fickle.StackedPickle.load(file, fail_on_decode_error=False)
        except fickle.PickleDecodeError as e:
            sys.stderr.write(f"Fickling failed to parse this pickle file. Error: {e!s}\n")
            return 1
        finally:
            if file not in (sys.stdin, sys.stdin.buffer):
                file.close()

        if args.inject_target >= len(stacked_pickled):
            sys.stderr.write(
                f"Error: --inject-target {args.inject_target} is too high; there are only "
                f"{len(stacked_pickled)} stacked pickle files in the input\n"
            )
            return 1

        buffer = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout

        for pickled in stacked_pickled[: args.inject_target]:
            pickled.dump(buffer)

        pickled = stacked_pickled[args.inject_target]
        if not isinstance(pickled[-1], fickle.Stop):
            sys.stderr.write(
                "Warning: The last opcode of the input file was expected to be STOP, but was "
                f"in fact {pickled[-1].info.name}"
            )

        pickled.insert_python_eval(
            args.inject,
            run_first=not args.run_last,
            use_output_as_unpickle_result=args.replace_result,
        )
        pickled.dump(buffer)

        for pickled in stacked_pickled[args.inject_target + 1 :]:
            pickled.dump(buffer)

        return 0

    # Handle --create flag
    if args.create:
        pickled = fickle.Pickled(
            [
                fickle.Global.create("__builtin__", "eval"),
                fickle.Mark(),
                fickle.Unicode(args.create.encode("utf-8")),
                fickle.Tuple(),
                fickle.Reduce(),
                fickle.Stop(),
            ]
        )
        if args.file == "-":
            file = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
        else:
            file = open(args.file, "wb")

        try:
            pickled.dump(file)
        finally:
            if file not in (sys.stdout, sys.stdout.buffer):
                file.close()

        return 0

    # Default: decompile the file
    if args.file == "-":
        file = sys.stdin.buffer if hasattr(sys.stdin, "buffer") else sys.stdin
    else:
        file = open(args.file, "rb")

    try:
        stacked_pickled = fickle.StackedPickle.load(file, fail_on_decode_error=False)
    except fickle.PickleDecodeError as e:
        sys.stderr.write(f"Fickling failed to parse this pickle file. Error: {e!s}\n")
        return 1
    finally:
        if file not in (sys.stdin, sys.stdin.buffer):
            file.close()

    var_id = 0
    for i, pickled in enumerate(stacked_pickled):
        interpreter = fickle.Interpreter(
            pickled, first_variable_id=var_id, result_variable=f"result{i}"
        )
        if args.trace:
            trace = tracing.Trace(interpreter)
            print(unparse(trace.run()))
        else:
            print(unparse(interpreter.to_ast()))
        var_id = interpreter.next_variable_id

    return 0
