from argparse import ArgumentParser, FileType
import sys

from astunparse import unparse

from .pickle import Pickled


def main() -> int:
    parser = ArgumentParser(description="fickle is a static analyzer and interpreter for Python pickle data")
    parser.add_argument("PICKLE_FILE", type=FileType("rb"), help="the pickle file to analyze")

    args = parser.parse_args()

    print(unparse(Pickled.load(args.PICKLE_FILE).ast))

    return 0


if __name__ == '__main__':
    sys.exit(main())
