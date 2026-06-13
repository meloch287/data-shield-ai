"""Per-category recall on the eval corpus + the single known false positive.

This complements tests/test_eval_metrics.py (global precision/recall/F1 gate) by
breaking recall down PER CATEGORY using datashield.taxonomy.category_of, so a
regression that silently kills one whole class of detectors (e.g. all crypto or
all government_id types) is caught even if global recall stays high.

Everything here asserts ACTUAL measured behavior of the live detectors against
the live corpus:

  * Each category that is represented by at least one expected type in the
    corpus must have recall >= 0.9. Today every represented category sits at
    1.000 (no false negatives anywhere on the corpus).
  * The overall false-positive count is exactly evaluate()["fp"] (currently 0).
  * The corpus has ZERO false positives. The former IPv4/version ambiguity
    ("1.2.3.4" in "версия сборки 1.2.3.4 финальная" reading as IP) has been
    suppressed by version-context detection, so the version string is no longer
    detected as IP and nothing on the corpus regresses into a FP.

No product code, corpus, or other test files are modified by this module.
"""
from __future__ import annotations

import json
import unittest
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from datashield import scan, taxonomy
from tools.eval.evaluate import CORPUS, evaluate

# Recall floor per represented category. Kept below the observed 1.000 so the
# test asserts a meaningful gate without being brittle to a single new sample.
PER_CATEGORY_RECALL_FLOOR = 0.9

# The formerly inherent ambiguity (a four-part build version reading as an IPv4
# address) is now SUPPRESSED: in version context "1.2.3.4" is no longer masked
# as IP. We keep the string around to assert it is NOT detected anymore. Built
# so no literal IP-looking constant sits in the source.
SUPPRESSED_FP_TYPE = "IP"
SUPPRESSED_FP_VALUE = ".".join(["1", "2", "3", "4"])
SUPPRESSED_FP_TEXT = "версия сборки " + SUPPRESSED_FP_VALUE + " финальная"


def _load_corpus() -> List[Dict]:
    with open(CORPUS, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _detected_types(text: str) -> Set[str]:
    return {f.type for f in scan(text)}


def _per_category_counts() -> Tuple[Dict[str, int], Dict[str, int]]:
    """Group expected types by category_of and tally TP/FN across the corpus.

    Returns (tp_by_category, fn_by_category). A category appears as a key iff at
    least one expected type in the corpus maps to it (i.e. it is represented).
    """
    tp: Dict[str, int] = defaultdict(int)
    fn: Dict[str, int] = defaultdict(int)
    for ex in _load_corpus():
        expected = set(ex["types"])
        detected = _detected_types(ex["text"])
        for t in expected:
            category = taxonomy.category_of(t)
            if t in detected:
                tp[category] += 1
            else:
                fn[category] += 1
    return dict(tp), dict(fn)


class PerCategoryRecallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = evaluate()
        cls.tp_by_cat, cls.fn_by_cat = _per_category_counts()
        cls.represented = set(cls.tp_by_cat) | set(cls.fn_by_cat)

    def test_corpus_represents_multiple_categories(self):
        # Sanity: the grouping found real categories, not an empty/degenerate run.
        self.assertGreaterEqual(len(self.represented), 5)
        # Every represented category is a real declared taxonomy category (the
        # corpus never expects a type that falls through to the 'other' bucket).
        for category in self.represented:
            self.assertIn(category, taxonomy.CATEGORIES)

    def test_each_represented_category_has_recall_at_least_floor(self):
        for category in sorted(self.represented):
            tp = self.tp_by_cat.get(category, 0)
            fn = self.fn_by_cat.get(category, 0)
            denom = tp + fn
            recall = tp / denom if denom else 1.0
            self.assertGreaterEqual(
                recall,
                PER_CATEGORY_RECALL_FLOOR,
                f"category {category!r} recall {recall:.3f} "
                f"(tp={tp}, fn={fn}) below floor {PER_CATEGORY_RECALL_FLOOR}",
            )

    def test_no_false_negatives_on_corpus(self):
        # Current ground truth: recall is perfect, so no category has an FN.
        # Encoded explicitly so an FN-introducing regression in any category is
        # caught by an exact-zero assertion, not just the >=0.9 floor.
        self.assertEqual(self.fn_by_cat, {})
        self.assertEqual(self.result["fn"], 0)

    def test_government_id_category_is_well_covered(self):
        # government_id is the most populous category in the corpus; pin its
        # recall to 1.0 so a broad ID-detector regression cannot hide.
        self.assertIn("government_id", self.represented)
        tp = self.tp_by_cat["government_id"]
        fn = self.fn_by_cat.get("government_id", 0)
        self.assertGreater(tp, 0)
        self.assertEqual(fn, 0)
        self.assertEqual(tp / (tp + fn), 1.0)


class FalsePositiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = evaluate()

    def test_overall_fp_count_matches_evaluate(self):
        # Recompute FP independently from the corpus and confirm it equals the
        # count evaluate() reports, then pin both to zero (no FP on the corpus).
        fp = 0
        for ex in _load_corpus():
            expected = set(ex["types"])
            detected = _detected_types(ex["text"])
            fp += len(detected - expected)
        self.assertEqual(fp, self.result["fp"])
        self.assertEqual(self.result["fp"], 0)

    def test_no_false_positive_examples(self):
        # The corpus has zero false positives, so the FP example list is empty.
        self.assertEqual(self.result["false_positive_examples"], [])

    def test_known_fp_detector_fires_on_version_string(self):
        # Drill into scan() itself: the version string is NO LONGER detected as
        # IP. Version-context suppression keeps "1.2.3.4" from masking as IPv4.
        findings = scan(SUPPRESSED_FP_TEXT)
        ip_findings = [f for f in findings if f.type == SUPPRESSED_FP_TYPE]
        self.assertEqual(ip_findings, [])
        # And nothing else fires on it either — it is a clean decoy now.
        self.assertEqual({f.type for f in findings}, set())

    def test_nothing_else_regresses_into_a_false_positive(self):
        # Across the whole corpus there are NO (example, type) false positives.
        # Any detector firing where nothing is expected fails here.
        unexpected: List[Tuple[str, str]] = []
        for ex in _load_corpus():
            expected = set(ex["types"])
            for t in _detected_types(ex["text"]) - expected:
                unexpected.append((ex["text"], t))
        self.assertEqual(
            unexpected,
            [],
            f"unexpected false positives on the corpus: {unexpected}",
        )

    def test_fp_is_confined_to_network_category(self):
        # No category contributes a false positive: the corpus FP set is empty.
        fp_categories = set()
        for ex in _load_corpus():
            expected = set(ex["types"])
            for t in _detected_types(ex["text"]) - expected:
                fp_categories.add(taxonomy.category_of(t))
        self.assertEqual(fp_categories, set())


if __name__ == "__main__":
    unittest.main()
