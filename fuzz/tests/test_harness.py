"""Tests for the fuzzing harness itself.

Imports neither atheris nor the generator, so ``make test`` covers them without a fuzzing
run. Still this project's 3.14 venv, though -- not the parent's.
"""

import sys
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fickling.fickle as op
import scan
import triage
from fickling.fickle import Pickled

BENIGN = Pickled([op.Proto.create(4), op.BinInt1(1), op.Stop()]).dumps()


class TestOracles(unittest.TestCase):
    def test_benign_pickle_is_not_a_finding(self):
        self.assertIsNone(scan.probe(BENIGN))

    def test_malformed_input_is_expected_not_reported(self):
        # A decode error is fickling's documented contract for garbage, not a bug.
        self.assertIsNone(scan.probe(b"\x80\x04not-a-pickle-at-all"))

    def test_empty_input_is_not_a_finding(self):
        self.assertIsNone(scan.probe(b""))

    def test_unexpected_exception_is_reported(self):
        # FLOAT has no fickling Opcode class, so parsing raises NotImplementedError rather
        # than the documented PickleDecodeError. Used here as a stable known-bad input.
        failure = scan.probe(b"F1.0\n.")
        self.assertIsNotNone(failure)
        self.assertEqual(failure.oracle, "scan")
        self.assertIn("NotImplementedError", failure.signature)

    def test_muting_via_env(self):
        with unittest.mock.patch.dict(
            "os.environ", {"FICKLING_FUZZ_EXPECTED": "NotImplementedError"}
        ):
            self.assertIsNone(scan.probe(b"F1.0\n."))

    def test_signature_distinguishes_distinct_bugs_at_the_same_line(self):
        # FLOAT and BYTEARRAY8 both raise NotImplementedError from the same line of
        # Opcode.__new__, so the frame alone cannot separate them. They must not collapse,
        # or only the first would ever be reported.
        float_sig = scan.probe(b"F1.0\n.").signature
        bytearray_sig = scan.probe(b"\x80\x05\x96\x01\x00\x00\x00\x00\x00\x00\x00a.").signature
        self.assertNotEqual(float_sig, bytearray_sig)

    def test_signature_is_usable_as_a_directory_name(self):
        sig = scan.probe(b"F1.0\n.").signature
        self.assertNotIn("/", sig)
        self.assertNotIn(":", sig)

    def test_normalize_message_collapses_input_derived_values(self):
        # Same bug, different integer: one report, not one per integer the fuzzer finds.
        self.assertEqual(
            scan.normalize_message("BINGET references non-existent memo key 2"),
            scan.normalize_message("BINGET references non-existent memo key 34567"),
        )

    def test_normalize_message_collapses_heap_addresses(self):
        # Fickling interpolates object reprs into messages. Without erasing the address the
        # same bug gets a brand new signature on every run and never converges.
        self.assertEqual(
            scan.normalize_message("found <ast.Tuple object at 0xffffb7ea80d0>"),
            scan.normalize_message("found <ast.Tuple object at 0xffffb7ea8370>"),
        )

    def test_normalize_message_collapses_opcode_repr_noise(self):
        # Same opcode, different stream offset and payload: one bug.
        self.assertEqual(
            scan.normalize_message(
                "Opcode Pop(info=<pickletools.OpcodeInfo object at 0xaaaa>, "
                "data=b'0', position=1132) attempted to pop from an empty stack"
            ),
            scan.normalize_message(
                "Opcode Pop(info=<pickletools.OpcodeInfo object at 0xbbbb>, "
                "data=b'1', position=77) attempted to pop from an empty stack"
            ),
        )

    def test_normalize_message_keeps_the_ast_node_type(self):
        # ast.Tuple and ast.Constant are different paths through the decompiler.
        self.assertNotEqual(
            scan.normalize_message("found <ast.Tuple object at 0xffffb7ea80d0>"),
            scan.normalize_message("found <ast.Constant object at 0xffffb7ea80d0>"),
        )

    def test_normalize_message_keeps_distinguishing_words(self):
        self.assertNotEqual(
            scan.normalize_message("TODO: Add support for Opcode FLOAT"),
            scan.normalize_message("TODO: Add support for Opcode BYTEARRAY8"),
        )

    def test_roundtrip_oracle_accepts_valid_pickles(self):
        for protocol in range(6):
            with self.subTest(protocol=protocol):
                data = Pickled([op.BinInt1(7), op.Stop()]).dumps()
                scan.oracle_roundtrip(data)  # must not raise


class TestTimeLimit(unittest.TestCase):
    """A scanner with no wall clock can be hung by one input, and without this the harness
    itself stalls and libFuzzer's -max_total_time stops meaning anything."""

    def test_slow_work_is_interrupted(self):
        def slow(_data):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                pass

        started = time.monotonic()
        failure = scan.probe(BENIGN, oracles=(("slow", slow),), time_limit_seconds=0.3)
        elapsed = time.monotonic() - started

        self.assertIsNotNone(failure, "a hang must be reported, not silently allowed")
        self.assertIsInstance(failure.exc, scan.ScanTimeout)
        self.assertLess(elapsed, 5, "the limit did not actually interrupt the work")

    def test_timeout_signature_collapses_interruption_points(self):
        # A timeout fires at an arbitrary line, so keying on the frame would file a fresh
        # report every time. All hangs in one oracle are one finding.
        def slow(_data):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                pass

        first = scan.probe(BENIGN, oracles=(("slow", slow),), time_limit_seconds=0.2)
        second = scan.probe(BENIGN, oracles=(("slow", slow),), time_limit_seconds=0.25)
        self.assertEqual(first.signature, second.signature)
        self.assertEqual(first.signature, "Timeout-slow")

    def test_timeout_survives_except_exception(self):
        # Fickling catches Exception broadly; a hang must not be absorbed into a clean scan.
        self.assertFalse(issubclass(scan.ScanTimeout, Exception))

    def test_limit_is_disarmed_afterwards(self):
        scan.probe(BENIGN, time_limit_seconds=5)
        # If the itimer were left running, this sleep would be interrupted.
        time.sleep(0.05)

    def test_zero_disables_the_limit(self):
        self.assertIsNone(scan.probe(BENIGN, time_limit_seconds=0))


class TestMinimizer(unittest.TestCase):
    def test_minimizes_to_the_essential_opcode(self):
        padding = [op.BinInt1(i % 256) for i in range(40)]
        noisy = Pickled([op.Proto.create(2), *padding, op.Stop()]).dumps() + b"F1.0\n."
        failure = scan.probe(noisy)
        self.assertIsNotNone(failure)

        minimal = triage.minimize(noisy, failure)
        self.assertLess(len(minimal), len(noisy))
        # Same bug, still reproducing.
        self.assertEqual(scan.probe(minimal).signature, failure.signature)

    def test_minimize_preserves_signature_and_never_grows(self):
        data = b"\x80\x04" + b"K\x01" * 30 + b"F1.0\n."
        failure = scan.probe(data)
        minimal = triage.minimize(data, failure)
        self.assertLessEqual(len(minimal), len(data))
        self.assertEqual(scan.probe(minimal).signature, failure.signature)

    def test_opcode_units_returns_none_for_garbage(self):
        self.assertIsNone(triage._opcode_units(b"\xff\xfe\xfd"))

    def test_opcode_units_covers_the_whole_input(self):
        units = triage._opcode_units(BENIGN)
        self.assertIsNotNone(units)
        self.assertEqual(b"".join(units), BENIGN)


class TestReproducerArtifacts(unittest.TestCase):
    def test_snippet_is_verified_for_a_supported_pickle(self):
        snippet, exact = triage.opcode_api_snippet(BENIGN)
        self.assertTrue(exact, f"expected an exact rebuild, got:\n{snippet}")
        self.assertIn("op.Proto.create(4)", snippet)
        self.assertIn("op.Stop()", snippet)

    def test_snippet_flags_unsupported_opcodes(self):
        snippet, exact = triage.opcode_api_snippet(b"F1.0\n.")
        self.assertFalse(exact)
        self.assertIn("FLOAT", snippet)

    def test_snippet_renders_global_via_factory(self):
        data = Pickled([op.Proto.create(2), op.Global.create("os", "system"), op.Stop()]).dumps()
        snippet, exact = triage.opcode_api_snippet(data)
        self.assertTrue(exact, f"expected an exact rebuild, got:\n{snippet}")
        self.assertIn("op.Global.create('os', 'system')", snippet)

    def test_emit_writes_a_complete_artifact_set(self):
        import tempfile

        data = b"F1.0\n."
        failure = scan.probe(data)
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp)
            written = triage.emit(outdir, data, data, failure)
            self.assertIsNotNone(written)
            for name in ("original.pkl", "minimal.pkl", "repro.py", "report.md"):
                self.assertTrue((written / name).exists(), f"missing {name}")
            self.assertEqual((written / "minimal.pkl").read_bytes(), data)

            report = (written / "report.md").read_text()
            self.assertIn("NotImplementedError", report)
            self.assertIn("Traceback", report)

            # The emitted reproducer must scan, never load.
            repro = (written / "repro.py").read_text()
            self.assertIn("check_safety", repro)
            self.assertNotIn("pickle.loads", repro)

            # Second emit for the same signature is a no-op, so replaying a crash a
            # thousand times does not churn the directory.
            self.assertIsNone(triage.emit(outdir, data, data, failure))

    def _run_emitted_repro(self, data: bytes):
        """Emit a reproducer for `data`, run it in-process, and return what it raised."""
        import tempfile

        failure = scan.probe(data)
        self.assertIsNotNone(failure, "expected this input to be a finding")
        with tempfile.TemporaryDirectory() as tmp:
            written = triage.emit(Path(tmp), data, data, failure)
            source = (written / "repro.py").read_text()

        namespace: dict = {"__name__": "repro_under_test"}
        exec(compile(source, "repro.py", "exec"), namespace)
        try:
            namespace["main"]()
        except BaseException as exc:  # noqa: BLE001 - whatever it raised is the result
            return failure, exc, source
        self.fail("the emitted reproducer exited cleanly instead of reproducing")

    def test_repro_reproduces_a_scan_oracle_finding(self):
        failure, raised, _ = self._run_emitted_repro(b"F1.0\n.")
        self.assertEqual(failure.oracle, "scan")
        self.assertIsInstance(raised, NotImplementedError)

    def test_repro_reproduces_a_decompile_oracle_finding(self):
        # The regression this guards: the template used to hardcode the scan path, so every
        # decompiler finding shipped a reproducer that exited cleanly.
        data = Pickled([op.Mark(), op.Dup(), op.Dict(), op.Dict(), op.Stop()]).dumps()
        failure, raised, source = self._run_emitted_repro(data)
        self.assertEqual(failure.oracle, "decompile")
        self.assertIn("pickled.ast", source)
        self.assertIsInstance(raised, ValueError)

    def test_repro_drives_the_path_the_minimized_bytes_trip(self):
        # emit() re-probes the minimized bytes, so the body matches reality even when the
        # oracle differs from the one that originally reported it.
        for data in (
            b"F1.0\n.",
            Pickled([op.Mark(), op.Dup(), op.Dict(), op.Dict(), op.Stop()]).dumps(),
        ):
            with self.subTest(data=data):
                _, _, source = self._run_emitted_repro(data)
                reprobed = scan.probe(data)
                _, body = triage._REPRO_BODIES[reprobed.oracle]
                self.assertIn(body.strip().splitlines()[0].strip(), source)

    def test_hang_reproducer_asserts_on_slowness(self):
        # A hang's oracle body completes, just slowly, so without a timing assertion the
        # script exits 0 and reads as "does not reproduce".
        source = triage.render_repro(BENIGN, "Timeout-scan", "scan", timeout_limit=2.0)
        self.assertIn("import time", source)
        self.assertIn("elapsed", source)
        self.assertIn("2.0", source)

    def test_non_hang_reproducer_has_no_timing_assertion(self):
        source = triage.render_repro(BENIGN, "sig", "scan")
        self.assertNotIn("elapsed", source)

    def test_hang_reproducer_exits_nonzero_when_fast(self):
        # A fast input under a hang reproducer must not silently pass as "reproduced".
        source = triage.render_repro(BENIGN, "Timeout-scan", "scan", timeout_limit=2.0)
        namespace: dict = {"__name__": "repro_under_test"}
        exec(compile(source, "repro.py", "exec"), namespace)
        with self.assertRaises(SystemExit):
            namespace["main"]()

    def test_every_oracle_has_a_reproducer_body(self):
        # A new oracle without a body would raise KeyError at emit time, losing the finding.
        for name, _fn in scan.ORACLES:
            self.assertIn(name, triage._REPRO_BODIES)

    def test_no_reproducer_body_deserializes(self):
        for name, (imports, body) in triage._REPRO_BODIES.items():
            with self.subTest(oracle=name):
                source = imports + body
                for forbidden in ("pickle.loads", "pickle.load", "Unpickler", "fickling.load"):
                    self.assertNotIn(forbidden, source)

    def test_disassembly_is_included_for_valid_pickles(self):
        self.assertIn("PROTO", triage._disassemble(BENIGN))

    def test_disassembly_degrades_on_truncated_input(self):
        out = triage._disassemble(b"\x80\x04K")
        self.assertIn("dis stopped", out)


class TestKnownPickleShapes(unittest.TestCase):
    """Sanity net: things the harness must classify correctly for real payloads."""

    def test_dangerous_pickle_is_scanned_not_reported_as_a_bug(self):
        # A malicious pickle is a high severity *result*, not a harness finding.
        data = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("os"),
                op.ShortBinUnicode("system"),
                op.StackGlobal(),
                op.ShortBinUnicode("echo pwned"),
                op.TupleOne(),
                op.Reduce(),
                op.Stop(),
            ]
        ).dumps()
        self.assertIsNone(scan.probe(data))

        from io import BytesIO

        from fickling.analysis import Severity, check_safety

        result = check_safety(Pickled.load(BytesIO(data)))
        self.assertGreater(result.severity, Severity.LIKELY_SAFE)

    def test_every_protocol_disassembles_and_scans(self):
        import pickle as stdlib_pickle

        for protocol in range(stdlib_pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                data = stdlib_pickle.dumps([1, "two", {3: None}], protocol=protocol)
                self.assertIsNone(scan.probe(data))


if __name__ == "__main__":
    unittest.main(verbosity=2)
