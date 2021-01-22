from argparse import ArgumentParser
import sys

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
            pickled.insert(-2, pickle.Global.create("__builtin__", "eval"))
            pickled.insert(-2, pickle.Mark())
            pickled.insert(-2, pickle.Unicode(args.inject.encode("utf-8")))
            pickled.insert(-2, pickle.Tuple())
            pickled.insert(-2, pickle.Reduce())
            # pop the stack to remove the result of calling eval
            pickled.insert(-2, pickle.Pop())
            print(pickled.dumps())
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
