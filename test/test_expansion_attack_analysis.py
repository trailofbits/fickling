"""
Tests for static detection of expansion attacks (Billion Laughs style)
via the ExpansionAttackAnalysis heuristic in check_safety().
"""

import pickle
from unittest import TestCase

from fickling.analysis import AnalysisContext, ExpansionAttackAnalysis, Severity, check_safety
from fickling.fickle import (
    Append,
    BinGet,
    BinPut,
    Dup,
    EmptyList,
    List,
    Mark,
    Memoize,
    Pickled,
    Proto,
    ShortBinUnicode,
    Stop,
)


class TestExpansionAttackAnalysis(TestCase):
    """Test static detection of expansion attacks via ExpansionAttackAnalysis.

    These tests verify that check_safety() detects suspicious opcode patterns
    indicative of Billion Laughs style DoS attacks without executing the pickle.
    """

    def test_memo_expansion_detection(self):
        """Test detection of high GET/PUT ratio patterns.

        Creates a pickle with many GET operations relative to PUT operations,
        which is characteristic of expansion attacks.
        """
        # Create a pickle with high GET/PUT ratio
        # 1 PUT followed by many GETs
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),  # PUT to memo[0]
        ]
        # Add many GETs
        for _ in range(60):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)
        result = check_safety(pickled)

        # Should detect the suspicious pattern
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)

    def test_dup_expansion_detection(self):
        """Test detection of excessive DUP operations.

        Creates a pickle with many DUP operations which could be used
        to exponentially expand the stack.
        """
        # Create a pickle with many DUP operations
        opcodes = [
            Proto.create(4),
            EmptyList(),
        ]
        # Add many DUPs (over threshold)
        opcodes.extend(Dup() for _ in range(150))
        opcodes.append(Stop())

        pickled = Pickled(opcodes)
        result = check_safety(pickled)

        # Should detect the suspicious pattern
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)

    def test_legitimate_data_not_flagged(self):
        """Test that legitimate pickle data is not falsely flagged.

        Large but legitimate data should pass without being flagged
        as an expansion attack.
        """
        large_list = list(range(100))
        data = pickle.dumps(large_list)

        pickled = Pickled.load(data)
        result = check_safety(pickled)

        self.assertEqual(result.severity, Severity.LIKELY_SAFE)

    def test_dup_nested_expansion_pattern(self):
        """Minimal reproduction of globalLaughs.pt DUP-based expansion attack.
        See: https://github.com/coldwaterq/pickle_injector/blob/main/globalLaughs.pt

        Original: 9 layers x 9 DUPs = 81 DUPs, 10^9 expansion from ~200 bytes.
        Minimal: 3 layers x 3 DUPs = 9 DUPs, 4^3 = 64 elements.
        """
        pickled = Pickled(
            [
                Proto.create(4),
                Mark(),
                Mark(),
                Mark(),
                ShortBinUnicode("lol"),
                Dup(),
                Dup(),
                Dup(),
                List(),
                Dup(),
                Dup(),
                Dup(),
                List(),
                Dup(),
                Dup(),
                Dup(),
                List(),
                Stop(),
            ]
        )

        analysis = ExpansionAttackAnalysis(dup_count_threshold=5)
        context = AnalysisContext(pickled)
        results = context.analyze(analysis)

        self.assertGreater(len(results), 0)
        self.assertTrue(any("DUP" in r.trigger for r in results if r.trigger))
        self.assertGreater(results[0].severity, Severity.LIKELY_SAFE)

    def test_memo_nested_expansion_pattern(self):
        """Minimal reproduction of billionLaughsAlt.pkl memo-based expansion attack.
        See: https://github.com/coldwaterq/pickle_injector/blob/main/billionLaughsAlt.pkl

        Uses BINPUT/BINGET instead of DUP to bypass parsers that disable DUP.
        Original: 10 layers, 10 PUTs, 90 GETs, ratio 9:1, 10^10 expansion.
        Minimal: 3 layers, 3 PUTs, 9 GETs, ratio 3:1, 4^3 = 64 elements.
        """
        pickled = Pickled(
            [
                Proto.create(4),
                Mark(),
                Mark(),
                Mark(),
                ShortBinUnicode("lol"),
                BinPut(0),
                BinGet(0),
                BinGet(0),
                BinGet(0),
                List(),
                BinPut(1),
                BinGet(1),
                BinGet(1),
                BinGet(1),
                List(),
                BinPut(2),
                BinGet(2),
                BinGet(2),
                BinGet(2),
                List(),
                Stop(),
            ]
        )

        analysis = ExpansionAttackAnalysis(
            get_put_ratio_threshold=2, high_get_put_ratio_threshold=5
        )
        context = AnalysisContext(pickled)
        results = context.analyze(analysis)

        self.assertGreater(len(results), 0)
        self.assertTrue(any("GET/PUT ratio" in r.trigger for r in results if r.trigger))
        self.assertGreater(results[0].severity, Severity.LIKELY_SAFE)

    def test_check_safety_catches_resource_exhaustion(self):
        """Test that check_safety returns a result instead of propagating
        ResourceExhaustionError when the pickle triggers resource limits."""
        opcodes = [
            Proto.create(4),
            EmptyList(),
            Memoize(),
        ]
        # 200 GETs with 1 PUT = ratio 200:1, exceeds default max_get_ratio=50
        for _ in range(200):
            opcodes.append(BinGet(0))
            opcodes.append(Append())
        opcodes.append(Stop())

        pickled = Pickled(opcodes)
        result = check_safety(pickled)

        # Static detection and/or runtime limits should flag this
        self.assertGreaterEqual(result.severity.severity, Severity.SUSPICIOUS.severity)
