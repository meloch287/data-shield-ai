"""Юнит-тесты гармонии eval (tools/eval/evaluate.py) и целостности корпуса.

Проверяем:
* математику precision/recall/f1, включая соглашения деления на ноль
  (нет positives -> precision/recall = 1.0; p+r == 0 -> f1 = 0.0);
* агрегацию evaluate() на крошечных рукотворных корпусах во временном файле
  (идеальный -> 1.0/1.0/1.0; полный промах -> recall 0; чистые ловушки с
  форсированным FP -> precision < 1);
* per_type — ключи и значения tp/fp/fn;
* false_positive_examples заполняется только когда срабатывают лишние типы;
* evaluate() на реальном корпусе даёт precision >= 0.95;
* целостность tools/eval/corpus.jsonl: каждая строка — валидный JSON, "types"
  — список, и каждый тип присутствует в настоящем каталоге детекторов.

Только stdlib unittest. Файл не редактирует продукт и корпус.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from datashield.config import Config
from datashield.detectors.registry import build_catalog
from tools.eval.evaluate import CORPUS, _prf, evaluate

# --- константы текстов, поведение которых проверено на реальном scan() ---
# email-текст -> детектируется ровно {EMAIL}
EMAIL_TEXT = "write to ivan.petrov@example.com today"
# чистая ловушка, на которой scan() ничего не находит
CLEAN_TEXT = "обычное предложение без каких-либо данных"
# 4-компонентный OID "2.5.29.17" по форме совпадает с IPv4 и форсирует
# единственный FP типа IP (используется как фикстура для проверки механики
# подсчёта FP в evaluate(); version-context "1.2.3.4" теперь подавлен и FP не
# даёт, поэтому в качестве форс-FP взят standalone-OID, который IP ещё ловит).
FORCED_FP_TEXT = "2.5.29.17"


def _write_corpus(rows):
    """Пишет список {"text","types"} во временный .jsonl и возвращает путь."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


class PrfMathTests(unittest.TestCase):
    """Прямые проверки _prf: формулы и соглашения деления на ноль."""

    def test_no_positives_precision_recall_one(self):
        # tp+fp == 0 и tp+fn == 0 -> и precision, и recall = 1.0, f1 = 1.0
        p, r, f = _prf(0, 0, 0)
        self.assertEqual(p, 1.0)
        self.assertEqual(r, 1.0)
        self.assertEqual(f, 1.0)

    def test_only_fn_recall_zero_precision_one(self):
        # ничего не нашли, но ожидали: precision=1.0 (нет tp+fp), recall=0.0
        p, r, f = _prf(0, 0, 1)
        self.assertEqual(p, 1.0)
        self.assertEqual(r, 0.0)
        # p + r != 0, но r == 0 -> f1 = 0.0
        self.assertEqual(f, 0.0)

    def test_only_fp_precision_zero_recall_one(self):
        p, r, f = _prf(0, 1, 0)
        self.assertEqual(p, 0.0)
        self.assertEqual(r, 1.0)
        self.assertEqual(f, 0.0)

    def test_f1_harmonic_mean(self):
        # tp=1, fp=1, fn=0 -> p=0.5, r=1.0, f1 = 2*0.5*1/(1.5) = 2/3
        p, r, f = _prf(1, 1, 0)
        self.assertEqual(p, 0.5)
        self.assertEqual(r, 1.0)
        self.assertAlmostEqual(f, 2.0 / 3.0)

    def test_perfect_counts(self):
        p, r, f = _prf(5, 0, 0)
        self.assertEqual((p, r, f), (1.0, 1.0, 1.0))

    def test_f1_zero_when_precision_and_recall_zero(self):
        # tp=0, fp>0, fn>0 -> p=0, r=0, p+r == 0 -> f1 ветка деления = 0.0
        p, r, f = _prf(0, 1, 1)
        self.assertEqual(p, 0.0)
        self.assertEqual(r, 0.0)
        self.assertEqual(f, 0.0)


class EvaluateTinyCorpusTests(unittest.TestCase):
    """evaluate() на крошечных рукотворных корпусах во временном файле."""

    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _corpus(self, rows):
        path = _write_corpus(rows)
        self._paths.append(path)
        return path

    def test_perfect_corpus_all_ones(self):
        path = self._corpus([{"text": EMAIL_TEXT, "types": ["EMAIL"]}])
        res = evaluate(path)
        self.assertEqual(res["examples"], 1)
        self.assertEqual(res["tp"], 1)
        self.assertEqual(res["fp"], 0)
        self.assertEqual(res["fn"], 0)
        self.assertEqual(res["precision"], 1.0)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(res["f1"], 1.0)
        # никаких лишних срабатываний -> список пуст
        self.assertEqual(res["false_positive_examples"], [])

    def test_all_miss_recall_zero(self):
        # ожидаем EMAIL на тексте без email -> ничего не найдено -> FN.
        path = self._corpus([{"text": CLEAN_TEXT, "types": ["EMAIL"]}])
        res = evaluate(path)
        self.assertEqual(res["tp"], 0)
        self.assertEqual(res["fp"], 0)
        self.assertEqual(res["fn"], 1)
        self.assertEqual(res["recall"], 0.0)
        # нет tp+fp -> precision по соглашению = 1.0
        self.assertEqual(res["precision"], 1.0)
        # recall == 0 -> f1 == 0
        self.assertEqual(res["f1"], 0.0)
        # промах — это FN, а не FP: список FP пуст
        self.assertEqual(res["false_positive_examples"], [])

    def test_pure_decoy_forced_fp_precision_below_one(self):
        # ловушка (types=[]), но scan находит IP -> единственный FP.
        path = self._corpus([{"text": FORCED_FP_TEXT, "types": []}])
        res = evaluate(path)
        self.assertEqual(res["tp"], 0)
        self.assertEqual(res["fp"], 1)
        self.assertEqual(res["fn"], 0)
        self.assertLess(res["precision"], 1.0)
        self.assertEqual(res["precision"], 0.0)  # tp=0,fp=1 -> 0/(0+1)=0
        # нет ожидаемых типов -> нет tp+fn -> recall = 1.0
        self.assertEqual(res["recall"], 1.0)
        # FP заполнен ровно типом IP
        self.assertEqual(len(res["false_positive_examples"]), 1)
        fpx = res["false_positive_examples"][0]
        self.assertEqual(fpx["text"], FORCED_FP_TEXT)
        self.assertEqual(fpx["false_positives"], ["IP"])

    def test_mixed_corpus_aggregates_counts(self):
        # один идеальный + один форс-FP -> tp=1, fp=1, fn=0.
        path = self._corpus([
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": FORCED_FP_TEXT, "types": []},
        ])
        res = evaluate(path)
        self.assertEqual(res["examples"], 2)
        self.assertEqual(res["tp"], 1)
        self.assertEqual(res["fp"], 1)
        self.assertEqual(res["fn"], 0)
        # precision = 1/(1+1) = 0.5, recall = 1/(1+0) = 1.0
        self.assertEqual(res["precision"], 0.5)
        self.assertEqual(res["recall"], 1.0)
        # f1 = 2*0.5*1/1.5 = 0.6667 (округление до 4 знаков)
        self.assertAlmostEqual(res["f1"], 0.6667, places=4)

    def test_blank_lines_skipped(self):
        # пустые строки в файле игнорируются: examples == число содержательных.
        path = _write_corpus([{"text": EMAIL_TEXT, "types": ["EMAIL"]}])
        self._paths.append(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n   \n")
        res = evaluate(path)
        self.assertEqual(res["examples"], 1)


class PerTypeAggregationTests(unittest.TestCase):
    """per_type — структура ключей и значений."""

    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _corpus(self, rows):
        path = _write_corpus(rows)
        self._paths.append(path)
        return path

    def test_per_type_records_tp(self):
        path = self._corpus([{"text": EMAIL_TEXT, "types": ["EMAIL"]}])
        res = evaluate(path)
        self.assertIn("EMAIL", res["per_type"])
        self.assertEqual(res["per_type"]["EMAIL"], {"tp": 1, "fp": 0, "fn": 0})

    def test_per_type_records_fp(self):
        path = self._corpus([{"text": FORCED_FP_TEXT, "types": []}])
        res = evaluate(path)
        self.assertIn("IP", res["per_type"])
        self.assertEqual(res["per_type"]["IP"], {"tp": 0, "fp": 1, "fn": 0})

    def test_per_type_records_fn(self):
        path = self._corpus([{"text": CLEAN_TEXT, "types": ["EMAIL"]}])
        res = evaluate(path)
        self.assertIn("EMAIL", res["per_type"])
        self.assertEqual(res["per_type"]["EMAIL"], {"tp": 0, "fp": 0, "fn": 1})

    def test_per_type_values_have_three_keys(self):
        path = self._corpus([
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": FORCED_FP_TEXT, "types": []},
        ])
        res = evaluate(path)
        for val in res["per_type"].values():
            self.assertEqual(set(val.keys()), {"tp", "fp", "fn"})
            for sub in val.values():
                self.assertIsInstance(sub, int)

    def test_per_type_sorted_keys(self):
        # per_type строится из sorted(per_type.items()) -> ключи отсортированы.
        path = self._corpus([
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": FORCED_FP_TEXT, "types": []},
        ])
        res = evaluate(path)
        keys = list(res["per_type"].keys())
        self.assertEqual(keys, sorted(keys))

    def test_per_type_sum_matches_global(self):
        path = self._corpus([
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": FORCED_FP_TEXT, "types": []},
            {"text": CLEAN_TEXT, "types": ["EMAIL"]},
        ])
        res = evaluate(path)
        tp = sum(v["tp"] for v in res["per_type"].values())
        fp = sum(v["fp"] for v in res["per_type"].values())
        fn = sum(v["fn"] for v in res["per_type"].values())
        self.assertEqual(tp, res["tp"])
        self.assertEqual(fp, res["fp"])
        self.assertEqual(fn, res["fn"])


class FalsePositiveExamplesTests(unittest.TestCase):
    """false_positive_examples заполняется только когда есть лишние типы."""

    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _corpus(self, rows):
        path = _write_corpus(rows)
        self._paths.append(path)
        return path

    def test_empty_when_no_extra_types(self):
        path = self._corpus([
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": CLEAN_TEXT, "types": []},
        ])
        res = evaluate(path)
        self.assertEqual(res["false_positive_examples"], [])

    def test_populated_only_for_fp_rows(self):
        # перемешиваем чистый, идеальный и форс-FP — попадает только последний.
        path = self._corpus([
            {"text": CLEAN_TEXT, "types": []},
            {"text": EMAIL_TEXT, "types": ["EMAIL"]},
            {"text": FORCED_FP_TEXT, "types": []},
        ])
        res = evaluate(path)
        self.assertEqual(len(res["false_positive_examples"]), 1)
        self.assertEqual(
            res["false_positive_examples"][0]["text"], FORCED_FP_TEXT
        )

    def test_fp_list_sorted(self):
        # false_positives хранится через sorted(extra).
        path = self._corpus([{"text": FORCED_FP_TEXT, "types": []}])
        res = evaluate(path)
        fps = res["false_positive_examples"][0]["false_positives"]
        self.assertEqual(fps, sorted(fps))


class RealCorpusMetricsTests(unittest.TestCase):
    """evaluate() на реальном корпусе соответствует гейту качества."""

    @classmethod
    def setUpClass(cls):
        cls.res = evaluate()

    def test_precision_at_least_095(self):
        self.assertGreaterEqual(self.res["precision"], 0.95)

    def test_recall_at_least_095(self):
        self.assertGreaterEqual(self.res["recall"], 0.95)

    def test_f1_at_least_095(self):
        self.assertGreaterEqual(self.res["f1"], 0.95)

    def test_result_shape(self):
        for key in (
            "examples", "tp", "fp", "fn",
            "precision", "recall", "f1",
            "per_type", "false_positive_examples",
        ):
            self.assertIn(key, self.res)
        self.assertIsInstance(self.res["per_type"], dict)
        self.assertIsInstance(self.res["false_positive_examples"], list)

    def test_counts_consistent(self):
        # глобальные tp/fp/fn совпадают с суммой по per_type.
        tp = sum(v["tp"] for v in self.res["per_type"].values())
        fp = sum(v["fp"] for v in self.res["per_type"].values())
        fn = sum(v["fn"] for v in self.res["per_type"].values())
        self.assertEqual(tp, self.res["tp"])
        self.assertEqual(fp, self.res["fp"])
        self.assertEqual(fn, self.res["fn"])

    def test_metrics_rounded_four_places(self):
        for key in ("precision", "recall", "f1"):
            val = self.res[key]
            self.assertEqual(round(val, 4), val)


class CorpusIntegrityTests(unittest.TestCase):
    """Целостность tools/eval/corpus.jsonl против настоящего каталога типов."""

    @classmethod
    def setUpClass(cls):
        cls.catalog_types = {
            info.detector.type for info in build_catalog(Config())
        }
        with open(CORPUS, encoding="utf-8") as fh:
            cls.raw_lines = fh.readlines()

    def test_corpus_path_exists(self):
        self.assertTrue(os.path.exists(CORPUS))

    def test_every_line_valid_json(self):
        for i, line in enumerate(self.raw_lines, 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:  # pragma: no cover
                self.fail(f"строка {i} — невалидный JSON: {exc}")

    def test_each_record_has_text_and_types(self):
        for line in self.raw_lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            self.assertIn("text", rec)
            self.assertIn("types", rec)
            self.assertIsInstance(rec["text"], str)

    def test_types_is_a_list(self):
        for line in self.raw_lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            self.assertIsInstance(rec["types"], list)

    def test_every_listed_type_is_real_catalog_type(self):
        for line in self.raw_lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            for t in rec["types"]:
                self.assertIsInstance(t, str)
                self.assertIn(
                    t, self.catalog_types,
                    f"тип {t!r} не найден в каталоге детекторов",
                )

    def test_corpus_has_examples(self):
        nonblank = [ln for ln in self.raw_lines if ln.strip()]
        self.assertGreaterEqual(len(nonblank), 40)

    def test_catalog_type_count(self):
        # каталог по умолчанию: 68 типов (75 детекторов).
        self.assertEqual(len(self.catalog_types), 68)


if __name__ == "__main__":
    unittest.main()
