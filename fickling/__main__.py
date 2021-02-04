import ast
from argparse import ArgumentParser
import itertools
import sys
from typing import Tuple

from astunparse import unparse

from . import pickle


def main() -> int:
    parser = ArgumentParser(description="fickle is a static analyzer and interpreter for Python pickle data")
    parser.add_argument("PICKLE_FILE", type=str, nargs="?", default="-", help="path to the pickle file to either "
                                                                              "analyze or create (default is '-' for "
                                                                              "STDIN/STDOUT)")
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--inject", "-i", type=str, default=None, help="inject the specified Python code to be run at "
                                                                        "the end of depickling, and output the "
                                                                        "resulting pickle data")
    options.add_argument("--create", "-c", type=str, default=None)
    parser.add_argument("--run-last", "-l", action="store_true", help="used with --inject to have the injected code "
                                                                      "run after the existing pickling code in "
                                                                      "PICKLE_FILE (default is for the injected code "
                                                                      "to be run before the existing code)")
    parser.add_argument("--replace-result", "-r", action="store_true",
                        help="used with --inject to replace the unpickling result of the code in PICKLE_FILE with the "
                             "return value of the injected code. Either way, the preexisting pickling code is still "
                             "executed.")
    options.add_argument("--check-safety", "-s", action="store_true",
                         help="Test if the given pickle file is known to be unsafe. If so, exit with non-zero status. "
                              "This test is not guaranteed correct; the pickle file may still be unsafe even if this "
                              "check exits with code zero.")

    args = parser.parse_args()

    if args.create is None:
        if args.PICKLE_FILE == "-":
            if hasattr(sys.stdin, "buffer") and sys.stdin.buffer is not None:
                file = sys.stdin.buffer
            else:
                file = sys.stdin
        else:
            file = open(args.PICKLE_FILE, "rb")
        try:
            pickled = pickle.Pickled.load(file)
        finally:
            file.close()

        if args.inject is not None:
            if not isinstance(pickled[-1], pickle.Stop):
                sys.stderr.write("Error: The last opcode of the input file was expected to be STOP, but was in fact "
                                 f"{pickled[-1].info.name}")
            pickled.insert_python_eval(
                args.inject,
                run_first=not args.run_last,
                use_output_as_unpickle_result=args.replace_result
            )
            if hasattr(sys.stdout, "buffer") and sys.stdout.buffer is not None:
                pickled.dump(sys.stdout.buffer)
            else:
                pickled.dump(sys.stdout)
        elif args.check_safety:
            properties = pickled.properties
            likely_safe = True
            reported_shortened_code = set()
            def shorten_code(node) -> Tuple[str, bool]:
                code = unparse(node).strip()
                if len(code) > 32:
                    cutoff = code.find("(")
                    if code[cutoff] == "(":
                        shortened_code = f"{code[:code.find('(')].strip()}(...)"
                    else:
                        shortened_code = code
                else:
                    shortened_code = code
                already_reported = shortened_code in reported_shortened_code
                reported_shortened_code.add(shortened_code)
                return shortened_code, already_reported

            for node in pickled.non_standard_imports():
                likely_safe = False
                shortened, already_reported = shorten_code(node)
                if not already_reported:
                    print(f"`{shortened}` imports a Python module that is not a part of the standard library; "
                          "this can execute arbitrary code and is inherently unsafe")
            overtly_bad_evals = []
            for node in properties.non_setstate_calls:
                if hasattr(node.func, "id") and node.func.id in properties.likely_safe_imports:
                    # if the call is to a constructor of an object imported from the Python standard library,
                    # it's probably okay
                    continue
                likely_safe = False
                shortened, already_reported = shorten_code(node)
                if shortened.startswith("eval(") or shortened.startswith("exec("):
                    # this is overtly bad, so record it and print it at the end
                    overtly_bad_evals.append(shortened)
                elif not already_reported:
                    print(f"Call to `{shortened}` can execute arbitrary code and is inherently unsafe")
            for node in pickled.unsafe_imports():
                likely_safe = False
                shortened, _ = shorten_code(node)
                print(f"`{shortened}` is suspicious and indicative of an overtly malicious pickle file")
            for overtly_bad_eval in overtly_bad_evals:
                print(f"Call to `{overtly_bad_eval}` is almost certainly evidence of a malicious pickle file")
            if likely_safe:
                sys.stderr.write("Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may "
                                 "still be unsafe.\n\nDo not unpickle this file if it is from an untrusted source!\n")
                return 0
            else:
                return 1
        else:
            print(unparse(pickled.ast))
    else:
        pickled = pickle.Pickled([
            pickle.Global.create("__builtin__", "eval"),
            pickle.Mark(),
            pickle.Unicode(args.create.encode("utf-8")),
            pickle.Tuple(),
            pickle.Reduce(),
            pickle.Stop()
        ])
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


if __name__ == '__main__':
    sys.exit(main())
