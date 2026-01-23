from __future__ import annotations

import sys
from argparse import ArgumentParser
from ast import unparse

from . import __version__, fickle, tracing
from .analysis import Severity, check_safety

DEFAULT_JSON_OUTPUT_FILE = "safety_results.json"


def _add_pickle_arguments(parser: ArgumentParser) -> None:
    """Add the standard pickle-related arguments to a parser."""
    parser.add_argument(
        "PICKLE_FILE",
        type=str,
        nargs="?",
        default="-",
        help="path to the pickle file to either "
        "analyze or create (default is '-' for "
        "STDIN/STDOUT)",
    )
    options = parser.add_mutually_exclusive_group()
    options.add_argument(
        "--inject",
        "-i",
        type=str,
        default=None,
        help="inject the specified Python code to be run at the end of unpickling, "
        "and output the resulting pickle data",
    )
    parser.add_argument(
        "--inject-target",
        type=int,
        default=0,
        help="some machine learning frameworks stack multiple pickles into the same model file; "
        "this option specifies the index of the pickle file in which to inject the code from the "
        "`--inject` command (default is 0)",
    )
    options.add_argument("--create", "-c", type=str, default=None)
    parser.add_argument(
        "--run-last",
        "-l",
        action="store_true",
        help="used with --inject to have the injected code "
        "run after the existing pickling code in "
        "PICKLE_FILE (default is for the injected code "
        "to be run before the existing code)",
    )
    parser.add_argument(
        "--replace-result",
        "-r",
        action="store_true",
        help=(
            "used with --inject to replace the unpickling result of the code in PICKLE_FILE "
            "with the return value of the injected code. Either way, the preexisting pickling "
            "code is still executed."
        ),
    )
    options.add_argument(
        "--check-safety",
        "-s",
        action="store_true",
        help=(
            "test if the given pickle file is known to be unsafe. If so, exit with non-zero "
            "status. This test is not guaranteed correct; the pickle file may still be unsafe "
            "even if this check exits with code zero."
        ),
    )

    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="path to the output JSON file to store the analysis results from check-safety."
        f"If not provided, a default file named {DEFAULT_JSON_OUTPUT_FILE} will be used.",
    )

    parser.add_argument(
        "--print-results",
        "-p",
        action="store_true",
        help="Print the analysis results to the console when checking safety.",
    )

    parser.add_argument(
        "--trace",
        "-t",
        action="store_true",
        help="print a runtime trace while interpreting the input pickle file",
    )


def _handle_pickle_command(args) -> int:
    """Handle the standard pickle decompilation/injection/safety commands."""
    if args.create is None:
        if args.PICKLE_FILE == "-":
            if hasattr(sys.stdin, "buffer") and sys.stdin.buffer is not None:
                file = sys.stdin.buffer
            else:
                file = sys.stdin
        else:
            file = open(args.PICKLE_FILE, "rb")
        try:
            stacked_pickled = fickle.StackedPickle.load(file, fail_on_decode_error=False)
        except fickle.PickleDecodeError as e:
            sys.stderr.write(f"Fickling failed to parse this pickle file. Error: {e!s}\n")
            if args.check_safety:
                sys.stderr.write(
                    "Parsing errors might be indicative of a maliciously crafted pickle file. DO NOT TRUST this file without performing further analysis!\n"
                )
                sys.stderr.write(
                    "\n(If this is a valid pickle file, please report the error at https://github.com/trailofbits/fickling)\n"
                )
            return 1
        finally:
            file.close()

        if args.inject is not None:
            if args.inject_target >= len(stacked_pickled):
                sys.stderr.write(
                    f"Error: --inject-target {args.inject_target} is too high; there are only "
                    f"{len(stacked_pickled)} stacked pickle files in the input\n"
                )
                return 1
            if hasattr(sys.stdout, "buffer") and sys.stdout.buffer is not None:
                buffer = sys.stdout.buffer
            else:
                buffer = sys.stdout
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
        elif args.check_safety:
            was_safe = True
            json_output_path = args.json_output or DEFAULT_JSON_OUTPUT_FILE
            for pickled in stacked_pickled:
                safety_results = check_safety(pickled, json_output_path=json_output_path)

                # Print results if requested
                if args.print_results:
                    print(safety_results.to_string())

                if safety_results.severity > Severity.LIKELY_SAFE:
                    was_safe = False
                    if args.print_results:
                        sys.stderr.write(
                            "Warning: Fickling detected that the pickle file may be unsafe.\n\n"
                            "Do not unpickle this file if it is from an untrusted source!\n\n"
                        )

            return [1, 0][was_safe]

        else:
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
    else:
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
        if args.PICKLE_FILE == "-":
            file = sys.stdout
            if hasattr(file, "buffer") and file.buffer is not None:
                file = file.buffer
        else:
            file = open(args.PICKLE_FILE, "wb")
        try:
            pickled.dump(file)
        finally:
            file.close()

    return 0


SUBCOMMANDS = {"pytorch", "polyglot"}


def _create_pickle_parser() -> ArgumentParser:
    """Create parser for the original pickle commands (backward compatibility)."""
    parser = ArgumentParser(
        description="fickling is a static analyzer and interpreter for Python pickle data"
    )
    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")
    _add_pickle_arguments(parser)
    return parser


def _create_subcommand_parser() -> ArgumentParser:
    """Create parser with subcommands for PyTorch and polyglot operations."""
    parser = ArgumentParser(
        description="fickling is a static analyzer and interpreter for Python pickle data"
    )
    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")

    subparsers = parser.add_subparsers(dest="command", help="available commands")

    # PyTorch subcommand
    pytorch_parser = subparsers.add_parser("pytorch", help="PyTorch model operations")
    _setup_pytorch_subcommand(pytorch_parser)

    # Polyglot subcommand
    polyglot_parser = subparsers.add_parser("polyglot", help="polyglot detection and creation")
    _setup_polyglot_subcommand(polyglot_parser)

    return parser


def _get_first_positional(argv: list[str]) -> str | None:
    """Get the first non-flag argument (potential subcommand or file)."""
    for arg in argv[1:]:
        if not arg.startswith("-"):
            return arg
    return None


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv

    # Check for version flag first
    if "--version" in argv or "-v" in argv:
        if sys.stdout.isatty():
            print(f"fickling version {__version__}")
        else:
            print(__version__)
        return 0

    # Determine if we're using a subcommand or the original CLI
    first_positional = _get_first_positional(argv)

    if first_positional in SUBCOMMANDS:
        # Use subcommand parser
        parser = _create_subcommand_parser()
        args = parser.parse_args(argv[1:])

        if args.command == "pytorch":
            from .cli_pytorch import handle_pytorch_command

            return handle_pytorch_command(args)
        if args.command == "polyglot":
            from .cli_polyglot import handle_polyglot_command

            return handle_polyglot_command(args)
        # Should not reach here
        return 1
    # Use original pickle parser for backward compatibility
    parser = _create_pickle_parser()
    args = parser.parse_args(argv[1:])
    return _handle_pickle_command(args)


def _setup_pytorch_subcommand(parser: ArgumentParser) -> None:
    """Set up the pytorch subcommand with its sub-subcommands."""
    subparsers = parser.add_subparsers(dest="pytorch_command", help="pytorch operations")

    # identify
    identify_parser = subparsers.add_parser("identify", help="detect PyTorch file format(s)")
    identify_parser.add_argument("file", type=str, help="path to the PyTorch model file")
    identify_parser.add_argument("--json", action="store_true", help="output results as JSON")

    # show
    show_parser = subparsers.add_parser("show", help="decompile internal pickle from PyTorch model")
    show_parser.add_argument("file", type=str, help="path to the PyTorch model file")
    show_parser.add_argument(
        "--force", "-f", action="store_true", help="force processing unsupported formats"
    )
    show_parser.add_argument("--trace", "-t", action="store_true", help="print a runtime trace")

    # check-safety
    safety_parser = subparsers.add_parser(
        "check-safety", help="run safety analysis on internal pickle"
    )
    safety_parser.add_argument("file", type=str, help="path to the PyTorch model file")
    safety_parser.add_argument(
        "--force", "-f", action="store_true", help="force processing unsupported formats"
    )
    safety_parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="path to output JSON file for analysis results",
    )
    safety_parser.add_argument(
        "--print-results", "-p", action="store_true", help="print results to console"
    )

    # inject
    inject_parser = subparsers.add_parser("inject", help="inject payload into PyTorch model")
    inject_parser.add_argument("file", type=str, help="path to the PyTorch model file")
    inject_parser.add_argument("-o", "--output", type=str, required=True, help="output file path")
    inject_parser.add_argument(
        "-c", "--code", type=str, required=True, help="Python code to inject"
    )
    inject_parser.add_argument(
        "--method",
        type=str,
        choices=["insertion", "combination"],
        default="insertion",
        help="injection method (default: insertion)",
    )
    inject_parser.add_argument(
        "--force", "-f", action="store_true", help="force processing unsupported formats"
    )
    inject_parser.add_argument(
        "--overwrite", action="store_true", help="overwrite original file with output"
    )


def _setup_polyglot_subcommand(parser: ArgumentParser) -> None:
    """Set up the polyglot subcommand with its sub-subcommands."""
    subparsers = parser.add_subparsers(dest="polyglot_command", help="polyglot operations")

    # identify
    identify_parser = subparsers.add_parser(
        "identify", help="identify all possible PyTorch file formats"
    )
    identify_parser.add_argument("file", type=str, help="path to the file to identify")
    identify_parser.add_argument("--json", action="store_true", help="output results as JSON")

    # properties
    properties_parser = subparsers.add_parser("properties", help="analyze file properties")
    properties_parser.add_argument("file", type=str, help="path to the file to analyze")
    properties_parser.add_argument(
        "-r", "--recursive", action="store_true", help="analyze recursively into archives"
    )
    properties_parser.add_argument("--json", action="store_true", help="output results as JSON")

    # create
    create_parser = subparsers.add_parser("create", help="create a polyglot file")
    create_parser.add_argument("file1", type=str, help="first input file")
    create_parser.add_argument("file2", type=str, help="second input file")
    create_parser.add_argument("-o", "--output", type=str, default=None, help="output file path")
    create_parser.add_argument(
        "--quiet", "-q", action="store_true", help="suppress output messages"
    )
