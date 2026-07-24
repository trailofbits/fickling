from unittest import TestCase

import fickling.fickle as op
from fickling.analysis import Severity, check_safety
from fickling.fickle import Pickled


class TestAnalysis(TestCase):
    def test_benign_pickle(self):
        pickled = Pickled(
            [
                op.Proto.create(4),
                op.ShortBinUnicode("collections"),
                op.ShortBinUnicode("deque"),
                op.StackGlobal(),
                op.Stop(),
            ]
        )
        self.assertEqual(check_safety(pickled).severity, Severity.LIKELY_SAFE)

    def test_severity_is_hashable(self):
        # Regression: Severity defines __eq__, which nulls __hash__ unless a
        # __hash__ is also defined. Without it, Severity members cannot be used
        # as dict keys or set members -- a natural way to group/classify results
        # (e.g. `severity in {Severity.OVERTLY_MALICIOUS, ...}`).
        self.assertIsNotNone(type(Severity.LIKELY_SAFE).__hash__)

        # set membership must work
        bad = {Severity.OVERTLY_MALICIOUS, Severity.LIKELY_OVERTLY_MALICIOUS}
        self.assertIn(Severity.OVERTLY_MALICIOUS, bad)
        self.assertNotIn(Severity.LIKELY_SAFE, bad)

        # every member must be usable as a dict key
        by_severity = {sev: sev.severity for sev in Severity}
        self.assertEqual(len(by_severity), len(list(Severity)))

        # hashing stays consistent with __eq__
        self.assertEqual(hash(Severity.SUSPICIOUS), hash(Severity.SUSPICIOUS))
