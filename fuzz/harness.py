#!/usr/bin/env python3
"""Structure-aware fuzzing harness for fickling's pickle scanner.

Pairs atheris (coverage feedback over instrumented Python) with
cisco-ai-defense/pickle-fuzzer (a Rust generator of structurally valid pickles). The
generator is wired in as an atheris ``custom_mutator`` rather than called from the test
function, which keeps libFuzzer's corpus in pickle space: corpus entries and crash
artifacts are themselves pickles, and ``-minimize_crash=1`` works natively.

    make fuzz               # 60s smoke run
    make fuzz ARGS='-max_total_time=600 -jobs=4'
    make check              # self-test, no fuzzing

Findings land in fuzz/artifacts/<signature>/ with a minimized pickle and a reproducer.
Nothing here deserializes.
"""

from __future__ import annotations

import argparse
import random
import shlex
import sys
from pathlib import Path

import atheris

# Without instrumentation there is no coverage signal to guide on. Scoped to the package
# because instrumenting the world is slow and buys nothing here.
with atheris.instrument_imports(include=["fickling"]):
    import fickling  # noqa: F401 - imported for its instrumentation side effect

from pickle_fuzzer import Generator

import scan
import triage

HERE = Path(__file__).resolve().parent
DEFAULT_ARTIFACTS = HERE / "artifacts"
PROTOCOLS = 6

#: Share of mutations that come from the generator. The rest are plain byte mutations,
#: which is how fickling's malformed-input paths get reached at all.
STRUCTURED_SHARE = 0.85

_generators: dict[int, Generator] = {}


def _generate(protocol: int, seed_bytes: bytes, max_size: int) -> bytes:
    """Structure-aware generation, reusing one Generator per protocol.

    ``reset()`` keeps generation a pure function of (protocol, seed_bytes). Without it a
    crash found now would not replay later, and the minimizer would chase a moving target.
    """
    gen = _generators.get(protocol)
    if gen is None:
        gen = _generators[protocol] = Generator(protocol=protocol, seed=protocol)
    gen.reset()
    return gen.generate_from_bytes(seed_bytes, max_size=max_size)


def custom_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    """Produce the next candidate pickle. Deterministic in (data, max_size, seed), which
    libFuzzer requires for replay."""
    rng = random.Random(seed)
    if rng.random() < STRUCTURED_SHARE:
        protocol = rng.randrange(PROTOCOLS)
        try:
            return _generate(protocol, data or bytes([seed & 0xFF]), max_size)
        except Exception:  # noqa: BLE001 - fall through to byte mutation
            pass
    mutated = atheris.Mutate(data, max_size) if data else bytes([seed & 0xFF])
    return mutated[:max_size]


def make_test_one_input(
    artifacts: Path, minimize: bool, exit_on_finding: bool, minimize_time: float
):
    """Build the fuzz target; `data` arrives as pickle bytes from `custom_mutator`.

    A finding does not stop the run by default. Fickling has failure modes reachable within
    the first second, so aborting on the first would rediscover the same bug every session.
    """
    # Signatures already on disk from an earlier session, so re-runs do not re-report.
    seen: set[str] = (
        {p.name for p in artifacts.iterdir() if p.is_dir()} if artifacts.exists() else set()
    )
    if seen:
        print(
            f"{len(seen)} known finding(s) in {artifacts}; delete a directory to have it "
            "reported again",
            file=sys.stderr,
        )

    def test_one_input(data: bytes) -> None:
        failure = scan.probe(data)
        if failure is None:
            return
        # Dedup before minimizing: delta debugging is by far the expensive part.
        if failure.signature not in seen:
            seen.add(failure.signature)
            minimal = (
                triage.minimize(data, failure, time_budget=minimize_time) if minimize else data
            )
            written = triage.emit(artifacts, data, minimal, failure)
            print(
                f"\n=== finding {len(seen)}: {failure}\n"
                f"    minimized {len(data)} -> {len(minimal)} bytes\n"
                f"    {written or artifacts / failure.signature}/report.md",
                file=sys.stderr,
                flush=True,
            )
        # Outside the dedup: -minimize_crash and artifact replay feed back an input whose
        # signature is already on disk, and swallowing the raise there makes a real crash
        # look clean ("the input did not crash"). Reporting dedups, the crash signal does not.
        if exit_on_finding:
            raise failure.exc

    return test_one_input


def _write_corpus(corpus: Path) -> int:
    """Seed a corpus of valid pickles across all six protocols, so coverage climbs
    immediately instead of after a few million rejections."""
    corpus.mkdir(parents=True, exist_ok=True)
    written = 0
    for protocol in range(PROTOCOLS):
        for i in range(8):
            try:
                data = _generate(protocol, bytes([protocol, i]) * (i + 1), 512)
            except Exception:  # noqa: BLE001
                continue
            (corpus / f"seed-p{protocol}-{i:02d}.pkl").write_bytes(data)
            written += 1
    return written


def _self_check() -> int:
    """Prove the harness works without fuzzing: the oracles behave and the generator runs."""
    benign = b"\x80\x04K\x01."  # PROTO 4, BININT1 1, STOP
    if scan.probe(benign) is not None:
        print("FAIL: a benign pickle was reported as a finding", file=sys.stderr)
        return 1
    print("oracles: benign pickle passes")

    if scan.probe(b"\x80\x04garbage-not-a-pickle") is not None:
        print("FAIL: malformed input should be an expected rejection", file=sys.stderr)
        return 1
    print("oracles: malformed input is rejected, not reported")

    generated = _generate(4, b"self-check", 256)
    print(f"generator: produced {len(generated)} bytes of protocol-4 pickle")
    print("\nself-check passed")
    return 0


def _relaunch_command(args: argparse.Namespace) -> str:
    """``argv[0]`` for the children libFuzzer spawns for -jobs, -fork and -minimize_crash.

    Those re-launch the target through ``sh`` instead of forking, rebuilding the command
    line from the flags libFuzzer itself knows. So two things break: ``sys.argv[0]`` is a
    script path that is neither on PATH nor executable, and this harness's own options never
    reach the child, leaving workers writing to the wrong artifacts directory and ignoring
    --exit-on-finding. Naming the interpreter and re-appending the options fixes both, and
    quoting survives the round trip through ``sh``, which word-splits the result back.
    """
    parts = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--artifacts",
        str(args.artifacts),
        "--time-limit",
        str(args.time_limit),
    ]
    if args.no_minimize:
        parts.append("--no-minimize")
    if args.exit_on_finding:
        parts.append("--exit-on-finding")
    if args.minimize_time is not None:
        parts += ["--minimize-time", str(args.minimize_time)]
    return " ".join(shlex.quote(part) for part in parts)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="harness.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--no-minimize", action="store_true", help="skip delta debugging")
    parser.add_argument(
        "--exit-on-finding",
        action="store_true",
        help="stop at the first new finding and let libFuzzer record it as a crash",
    )
    parser.add_argument(
        "--minimize-time",
        type=float,
        metavar="SECONDS",
        help="per-finding delta debugging budget (default: 5 while fuzzing, 60 for --replay)",
    )
    parser.add_argument(
        "--time-limit",
        type=float,
        default=scan.DEFAULT_TIME_LIMIT,
        metavar="SECONDS",
        help=(
            "per-input wall-clock ceiling; exceeding it is reported as a hang "
            f"(default: {scan.DEFAULT_TIME_LIMIT}, 0 disables)"
        ),
    )
    parser.add_argument("--check", action="store_true", help="self-test and exit")
    parser.add_argument("--summary", action="store_true", help="list recorded findings and exit")
    parser.add_argument("--write-corpus", type=Path, metavar="DIR", help="seed a corpus and exit")
    parser.add_argument(
        "--replay", type=Path, nargs="+", metavar="FILE", help="scan saved pickles and exit"
    )
    args, libfuzzer_args = parser.parse_known_args(argv[1:])

    # Applies to the minimizer's probes too, so one slow candidate cannot stall it.
    scan.DEFAULT_TIME_LIMIT = args.time_limit

    if args.check:
        return _self_check()

    if args.summary:
        return _summary(args.artifacts)

    if args.write_corpus:
        count = _write_corpus(args.write_corpus)
        print(f"wrote {count} seeds to {args.write_corpus}")
        return 0

    if args.replay:
        # One-shot triage can afford to minimize far harder than the fuzz loop, where this
        # time is spent per finding on top of -max_total_time.
        budget = args.minimize_time if args.minimize_time is not None else 60.0
        return _replay(args.replay, args.artifacts, not args.no_minimize, budget)

    args.artifacts.mkdir(parents=True, exist_ok=True)
    target = make_test_one_input(
        args.artifacts,
        not args.no_minimize,
        args.exit_on_finding,
        args.minimize_time if args.minimize_time is not None else 5.0,
    )
    # Keep libFuzzer's own crash/timeout units next to our reports instead of in the cwd.
    if not any(a.startswith("-artifact_prefix=") for a in libfuzzer_args):
        libfuzzer_args.append(f"-artifact_prefix={args.artifacts}/")
    atheris.Setup([_relaunch_command(args), *libfuzzer_args], target, custom_mutator=custom_mutator)
    # Does not return: libFuzzer exits the process itself, without unwinding Python. Anything
    # worth reporting has to be printed as it is found; `--summary` recaps afterwards.
    atheris.Fuzz()
    return 0


def _summary(artifacts: Path) -> int:
    """List the findings recorded so far."""
    found = sorted(p for p in artifacts.iterdir() if p.is_dir()) if artifacts.exists() else []
    if not found:
        print(f"no findings in {artifacts}")
        return 0
    print(f"{len(found)} finding(s) in {artifacts}:\n")
    for path in found:
        minimal = path / "minimal.pkl"
        size = f"{len(minimal.read_bytes())}b" if minimal.exists() else "?"
        print(f"  {path.name}  ({size} minimized)")
    return 0


def _replay(paths: list[Path], artifacts: Path, minimize: bool, minimize_time: float) -> int:
    """Re-scan saved pickles and re-emit their reports. The triage entry point."""
    findings = 0
    for path in paths:
        data = path.read_bytes()
        failure = scan.probe(data)
        if failure is None:
            print(f"{path}: clean")
            continue
        findings += 1
        minimal = triage.minimize(data, failure, time_budget=minimize_time) if minimize else data
        written = triage.emit(artifacts, data, minimal, failure)
        where = f" -> {written}/report.md" if written else " (already reported)"
        print(f"{path}: {failure} [{len(data)} -> {len(minimal)} bytes]{where}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
