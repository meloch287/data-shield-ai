"""Гейт качества: precision/recall/F1 на размеченном корпусе не должны падать."""
import unittest

from tools.eval.evaluate import evaluate


class EvalMetricsTests(unittest.TestCase):
    def setUp(self):
        self.result = evaluate()

    def test_corpus_nonempty(self):
        self.assertGreaterEqual(self.result["examples"], 40)

    def test_precision_threshold(self):
        self.assertGreaterEqual(self.result["precision"], 0.95)

    def test_recall_threshold(self):
        self.assertGreaterEqual(self.result["recall"], 0.95)

    def test_f1_threshold(self):
        self.assertGreaterEqual(self.result["f1"], 0.95)

    def test_false_positives_bounded(self):
        # На текущем корпусе 0 ложных срабатываний (версия/OID подавлены).
        self.assertEqual(self.result["fp"], 0)


if __name__ == "__main__":
    unittest.main()
