from argparse import ArgumentParser, FileType
import sys

from astunparse import unparse

from . import pickle


def main() -> int:
    parser = ArgumentParser(description="fickle is a static analyzer and interpreter for Python pickle data")
    parser.add_argument("PICKLE_FILE", type=FileType("rb"), help="the pickle file to analyze")
    parser.add_argument("--inject", "-i", type=str, default=None, help="inject the specified Python code to be run at "
                                                                       "the end of depickling, and output the "
                                                                       "resulting pickle data")

    args = parser.parse_args()

    pickled = pickle.Pickled.load(args.PICKLE_FILE)

    if args.inject is not None:
        pickled.insert(-2, pickle.Global.create("__builtins__", "eval"))
        pickled.insert(-2, pickle.Mark())
        pickled.insert(-2, pickle.Unicode(args.inject.encode("utf-8")))
        pickled.insert(-2, pickle.Tuple())
        pickled.insert(-2, pickle.Reduce())
        print(pickled.dumps())
    else:
        print(unparse(pickled.ast))

    return 0


if __name__ == '__main__':
    sys.exit(main())
