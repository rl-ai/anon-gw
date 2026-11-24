"""Release gate: the secret gate must catch EVERY positive fixture (zero leaks)
and report precision on the benign corpus. This is the leak-risk gate from the
v0.2.1 plan (Codex review #2): a miss on a known regression case blocks release."""
import os
import unittest

from anon_gw.secrets import SecretLeak, scan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "secrets")


class CorpusGateTests(unittest.TestCase):
    """Gate semantics: recall must be 1.0 (fail release on any miss)."""

    def test_zero_leaks_on_known_positives(self):
        positives = sorted(os.listdir(os.path.join(FIXTURES, "positive")))
        self.assertTrue(positives, "corpus missing")
        misses = []
        for name in positives:
            with open(os.path.join(FIXTURES, "positive", name)) as fh:
                text = fh.read()
            try:
                scan(text)
                misses.append(name)
            except SecretLeak:
                pass
        self.assertEqual(misses, [], f"RELEASE BLOCKED - credential leaks: {misses}")

    def test_precision_on_benign_corpus(self):
        negatives = sorted(os.listdir(os.path.join(FIXTURES, "negative")))
        self.assertTrue(negatives, "corpus missing")
        false_positives = []
        for name in negatives:
            with open(os.path.join(FIXTURES, "negative", name)) as fh:
                text = fh.read()
            try:
                scan(text)
            except SecretLeak:
                false_positives.append(name)
        # reported, not gated (over-blocking is a friction bug, not a leak);
        # the report feeds the published precision number
        self.assertEqual(false_positives, [],
                         f"false positives (friction, reported): {false_positives}")


if __name__ == "__main__":
    unittest.main()
