import sys
from argparse import ArgumentParser
from typing import List, Optional

if sys.version_info >= (3, 9):
    from ast import unparse
else:
    from astunparse import unparse

from . import __version__, pickle, tracing
from .analysis import check_safety


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv

    parser = ArgumentParser(
        description="fickle is a static analyzer and interpreter for Python pickle data"
    )
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
        help="inject the specified Python code to be run at the end of depickling, "
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
        "--trace",
        "-t",
        action="store_true",
        help="print a runtime trace while interpreting the input pickle file",
    )
    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")

    args = parser.parse_args(argv[1:])

    if args.version:
        if sys.stdout.isatty():
            print(f"fickling version {__version__}")
        else:
            print(__version__)
        return 0

    if args.create is None:
        if args.PICKLE_FILE == "-":
            if hasattr(sys.stdin, "buffer") and sys.stdin.buffer is not None:
                file = sys.stdin.buffer
            else:
                file = sys.stdin
        else:
            file = open(args.PICKLE_FILE, "rb")
        try:
            stacked_pickled = pickle.StackedPickle.load(file)
        except pickle.PickleDecodeError as e:
            sys.stderr.write(f"Error: {str(e)}\n")
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
            if not isinstance(pickled[-1], pickle.Stop):
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
            for pickled in stacked_pickled:
                if not check_safety(pickled):
                    was_safe = False
            return [1, 0][was_safe]
        else:
            var_id = 0
            for i, pickled in enumerate(stacked_pickled):
                interpreter = pickle.Interpreter(
                    pickled, first_variable_id=var_id, result_variable=f"result{i}"
                )
                if args.trace:
                    trace = tracing.Trace(interpreter)
                    print(unparse(trace.run()))
                else:
                    print(unparse(interpreter.to_ast()))
                var_id = interpreter.next_variable_id
    else:
        pickled = pickle.Pickled(
            [
                pickle.Global.create("__builtin__", "eval"),
                pickle.Mark(),
                pickle.Unicode(args.create.encode("utf-8")),
                pickle.Tuple(),
                pickle.Reduce(),
                pickle.Stop(),
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
