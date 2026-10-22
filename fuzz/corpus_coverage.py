#!/usr/bin/env python3
"""Replay a corpus through the oracles so coverage.py can measure what it reaches.

libFuzzer's own ``cov:`` counter is an edge count with no source mapping, so it says
coverage went up without saying of what.

Does not import ``harness``, and so never imports atheris: atheris rewrites fickling's
bytecode to insert its own counters, and coverage.py would then measure the rewritten
module rather than the source. Same inputs, same `scan.probe`, no fuzzer around them.

    make coverage
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import scan

HERE = Path(__file__).resolve().parent


def replay(paths: list[Path]) -> tuple[int, int]:
    """Probe every input, returning (probed, findings)."""
    findings = 0
    for path in paths:
        if scan.probe(path.read_bytes()) is not None:
            findings += 1
    return len(paths), findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="corpus_coverage.py", description=__doc__)
    parser.add_argument(
        "corpus",
        type=Path,
        nargs="*",
        default=[HERE / "corpus"],
        help="corpus directories or individual pickles (default: fuzz/corpus)",
    )
    parser.add_argument(
        "--time-limit",
        type=float,
        default=scan.DEFAULT_TIME_LIMIT,
        metavar="SECONDS",
        help=(
            "per-input ceiling, as in the harness; corpora accumulate slow inputs "
            f"(default: {scan.DEFAULT_TIME_LIMIT})"
        ),
    )
    args = parser.parse_args(argv[1:])
    scan.DEFAULT_TIME_LIMIT = args.time_limit

    paths: list[Path] = []
    for entry in args.corpus:
        if entry.is_dir():
            paths.extend(sorted(p for p in entry.rglob("*") if p.is_file()))
        elif entry.is_file():
            paths.append(entry)
        else:
            print(f"corpus_coverage: no such path: {entry}", file=sys.stderr)
            return 2

    if not paths:
        print(
            "corpus_coverage: nothing to replay. Seed a corpus first: make fuzz",
            file=sys.stderr,
        )
        return 2

    probed, findings = replay(paths)
    print(f"replayed {probed} input(s); {findings} reproduced a finding")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
