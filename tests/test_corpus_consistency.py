"""Внутренняя согласованность eval-корпуса с продуктом (Block F).

Проверяем, что committed-корпус tools/eval/corpus.jsonl согласован с поведением
продукта:

* Для каждого ПОЗИТИВНОГО примера все размеченные типы РЕАЛЬНО находятся scan()
  (recall на корпусе = 1.0, ни одного FN).
* Для каждой ЛОВУШКИ (types == []) фиксируем фактические детекции.
* build_corpus.py ДЕТЕРМИНИРОВАН: EXAMPLES -> байты не зависят от запуска, main()
  в temp-файл дважды даёт идентичные байты, и сборка совпадает с committed-файлом.
* Сконструированные образцы CARD/CARD2/AADH/CN_ID реально проходят
  luhn_check / verhoeff_check / china mod-11.

Тест НИЧЕГО не пишет в реальный corpus.jsonl и не правит продукт. Все записи —
только во временные файлы. Запуск:

    cd /Users/meloch287/Desktop/data-shield-ai
    python3 -m unittest tests.test_corpus_consistency -v
"""
from __future__ import annotations

import importlib
import json
import os
import tempfile
import unittest

import tools.eval.build_corpus as build_corpus
from datashield import scan
from datashield.validators import luhn_check
from datashield.validators_intl import verhoeff_check
from tools.eval.evaluate import evaluate

CORPUS_PATH = os.path.join(os.path.dirname(build_corpus.__file__), "corpus.jsonl")

# Веса и коды контрольной цифры китайского удостоверения (мод-11), как в продукте
# и в build_corpus.china_id.
_CHINA_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CHINA_CODES = "10X98765432"


def _load_corpus(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _write_examples(path, examples):
    """Повторяет логику build_corpus.main() записи (детерминированной)."""
    with open(path, "w", encoding="utf-8") as fh:
        for text, types in examples:
            fh.write(
                json.dumps({"text": text, "types": sorted(types)}, ensure_ascii=False)
                + "\n"
            )


class CorpusRecallConsistencyTests(unittest.TestCase):
    """Каждый позитивный пример: размеченные типы действительно детектируются."""

    @classmethod
    def setUpClass(cls):
        cls.corpus = _load_corpus(CORPUS_PATH)

    def test_corpus_nonempty(self):
        # Соответствует ожиданию quality-gate: >= 40 примеров.
        self.assertGreaterEqual(len(self.corpus), 40)

    def test_every_positive_example_has_all_labeled_types_detected(self):
        """Для каждого позитива expected_types подмножество detected_types (нет FN)."""
        missing = []
        for ex in self.corpus:
            expected = set(ex["types"])
            if not expected:
                continue  # ловушки проверяются отдельно
            detected = {f.type for f in scan(ex["text"])}
            not_found = expected - detected
            if not_found:
                missing.append((ex["text"], sorted(not_found)))
        self.assertEqual(
            missing,
            [],
            f"Корпус помечает типы, которые scan() не находит (ложные FN): {missing}",
        )

    def test_corpus_recall_is_one_no_false_negatives(self):
        """Агрегированный recall по корпусу = 1.0, fn == 0 (как измерено)."""
        result = evaluate(CORPUS_PATH)
        self.assertEqual(result["fn"], 0, "На корпусе не должно быть FN")
        self.assertEqual(result["recall"], 1.0, "Recall по корпусу должен быть 1.0")

    def test_positive_examples_have_at_least_one_finding(self):
        """Каждый позитив реально даёт хотя бы одну детекцию."""
        for ex in self.corpus:
            if not ex["types"]:
                continue
            findings = scan(ex["text"])
            self.assertTrue(
                findings,
                f"Позитив без детекций: {ex['text']!r}",
            )

    def test_corpus_types_are_sorted_as_committed(self):
        """types в каждой строке отсортированы (инвариант сериализации main())."""
        for ex in self.corpus:
            self.assertEqual(
                ex["types"],
                sorted(ex["types"]),
                f"types не отсортированы: {ex!r}",
            )


class CorpusDecoyDetectionTests(unittest.TestCase):
    """Ловушки (types == []): фиксируем фактическое поведение scan()."""

    @classmethod
    def setUpClass(cls):
        cls.corpus = _load_corpus(CORPUS_PATH)
        cls.decoys = [ex for ex in cls.corpus if ex["types"] == []]

    def test_corpus_has_decoys(self):
        self.assertGreater(len(self.decoys), 0, "В корпусе должны быть ловушки")

    def test_record_decoy_detections_match_measured_fp(self):
        """Суммарные детекции по ловушкам == измеренный FP корпуса.

        Все ожидаемые типы у ловушек пусты, поэтому любая детекция на ловушке —
        это FP в метрике evaluate(). Фиксируем фактическое число.
        """
        decoy_detections = []
        for ex in self.decoys:
            detected = sorted({f.type for f in scan(ex["text"])})
            if detected:
                decoy_detections.append((ex["text"], detected))
        # Все FP корпуса приходятся именно на ловушки (у позитивов FP=0 по факту),
        # поэтому суммарное число детекций по ловушкам совпадает с result['fp'].
        total_decoy_detections = sum(len(d) for _, d in decoy_detections)
        result = evaluate(CORPUS_PATH)
        self.assertEqual(
            total_decoy_detections,
            result["fp"],
            f"Детекции на ловушках не сходятся с FP={result['fp']}: "
            f"{decoy_detections}",
        )

    def test_no_decoy_produces_any_detection(self):
        """Ни одна ловушка не даёт детекций: FP корпуса == 0.

        После подавления version-context и ASN.1 OID версия '1.2.3.4'
        больше НЕ маскируется как IP, поэтому на ловушках не остаётся ни
        одной находки, а evaluate()['fp'] равен нулю.
        """
        decoy_detections = {}
        for ex in self.decoys:
            detected = sorted({f.type for f in scan(ex["text"])})
            if detected:
                decoy_detections[ex["text"]] = detected
        self.assertEqual(
            decoy_detections,
            {},
            f"Ловушки не должны давать детекций, но нашлись: {decoy_detections}",
        )
        result = evaluate(CORPUS_PATH)
        self.assertEqual(result["fp"], 0, "На корпусе не должно быть FP")

    def test_decoy_without_keyword_inn_form_not_detected(self):
        """Ловушка 'число 7707083893 просто так' (ИНН-форма без ключа) — без INN."""
        text = "число 7707083893 просто так"
        # Подтверждаем, что эта строка присутствует в корпусе как ловушка.
        self.assertIn({"text": text, "types": []}, self.corpus)
        detected = {f.type for f in scan(text)}
        self.assertNotIn("INN", detected)


class BuildCorpusDeterminismTests(unittest.TestCase):
    """build_corpus.py детерминирован и согласован с committed-файлом."""

    def test_examples_serialization_is_deterministic(self):
        """Двойная сериализация EXAMPLES в temp-файлы даёт идентичные байты."""
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.jsonl")
            b = os.path.join(d, "b.jsonl")
            _write_examples(a, build_corpus.EXAMPLES)
            _write_examples(b, build_corpus.EXAMPLES)
            with open(a, "rb") as fa, open(b, "rb") as fb:
                self.assertEqual(fa.read(), fb.read())

    def test_main_writes_identical_bytes_twice(self):
        """main() в temp-OUT дважды -> идентичные байты. Реальный corpus не трогаем."""
        original_out = build_corpus.OUT
        try:
            with tempfile.TemporaryDirectory() as d:
                first = os.path.join(d, "one.jsonl")
                second = os.path.join(d, "two.jsonl")
                build_corpus.OUT = first
                build_corpus.main()
                build_corpus.OUT = second
                build_corpus.main()
                with open(first, "rb") as f1, open(second, "rb") as f2:
                    self.assertEqual(f1.read(), f2.read())
        finally:
            build_corpus.OUT = original_out

    def test_main_does_not_modify_committed_corpus(self):
        """main() в temp-OUT не меняет байты committed corpus.jsonl."""
        with open(CORPUS_PATH, "rb") as fh:
            before = fh.read()
        original_out = build_corpus.OUT
        try:
            with tempfile.TemporaryDirectory() as d:
                build_corpus.OUT = os.path.join(d, "tmp.jsonl")
                build_corpus.main()
        finally:
            build_corpus.OUT = original_out
        with open(CORPUS_PATH, "rb") as fh:
            after = fh.read()
        self.assertEqual(before, after, "main() с temp-OUT не должен менять committed файл")

    def test_build_output_matches_committed_corpus_bytes(self):
        """Свежая сборка EXAMPLES байт-в-байт совпадает с committed corpus.jsonl."""
        with tempfile.TemporaryDirectory() as d:
            built = os.path.join(d, "built.jsonl")
            _write_examples(built, build_corpus.EXAMPLES)
            with open(built, "rb") as fb, open(CORPUS_PATH, "rb") as fc:
                self.assertEqual(
                    fb.read(),
                    fc.read(),
                    "committed corpus.jsonl разошёлся с build_corpus.EXAMPLES",
                )

    def test_module_reimport_yields_same_examples(self):
        """Повторный импорт модуля даёт ту же EXAMPLES (нет зависимости от состояния)."""
        snapshot = list(build_corpus.EXAMPLES)
        reloaded = importlib.reload(build_corpus)
        try:
            self.assertEqual(list(reloaded.EXAMPLES), snapshot)
        finally:
            # Возвращаем ссылку на актуальный модуль для остальных тестов.
            importlib.reload(build_corpus)


class ConstructedSampleChecksumTests(unittest.TestCase):
    """CARD / CARD2 / AADH / CN_ID реально проходят свои контрольные суммы."""

    def test_card_passes_luhn(self):
        self.assertTrue(luhn_check(build_corpus.CARD))

    def test_card2_passes_luhn(self):
        self.assertTrue(luhn_check(build_corpus.CARD2))

    def test_card_is_visa_like_16_digits(self):
        self.assertTrue(build_corpus.CARD.isdigit())
        self.assertEqual(len(build_corpus.CARD), 16)
        self.assertTrue(build_corpus.CARD.startswith("4"))  # Visa-like

    def test_aadhaar_passes_verhoeff(self):
        self.assertTrue(verhoeff_check(build_corpus.AADH))

    def test_aadhaar_is_12_digits(self):
        self.assertTrue(build_corpus.AADH.isdigit())
        self.assertEqual(len(build_corpus.AADH), 12)

    def test_china_id_passes_mod11_check_digit(self):
        cn = build_corpus.CN_ID
        self.assertEqual(len(cn), 18)
        base17 = cn[:17]
        expected_check = _CHINA_CODES[
            sum(int(base17[i]) * _CHINA_WEIGHTS[i] for i in range(17)) % 11
        ]
        self.assertEqual(cn[17], expected_check)

    def test_constructed_samples_are_present_in_committed_corpus(self):
        """Сконструированные значения реально попали в committed corpus."""
        with open(CORPUS_PATH, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertIn(build_corpus.CARD2, raw)  # 'card 5500005555555559'
        self.assertIn(build_corpus.AADH, raw)   # 'Aadhaar 234123412346'
        self.assertIn(build_corpus.CN_ID, raw)  # '身份证 110101199003071233'
        # CARD вставлена с пробелами по 4 цифры — проверяем сгруппированную форму.
        grouped = (
            f"{build_corpus.CARD[:4]} {build_corpus.CARD[4:8]} "
            f"{build_corpus.CARD[8:12]} {build_corpus.CARD[12:]}"
        )
        self.assertIn(grouped, raw)

    def test_constructed_card_samples_are_detected_as_credit_card(self):
        """Сконструированные карты реально детектируются как CREDIT_CARD."""
        for card in (build_corpus.CARD, build_corpus.CARD2):
            detected = {f.type for f in scan(card)}
            self.assertIn("CREDIT_CARD", detected, f"{card} не распознан как карта")


if __name__ == "__main__":
    unittest.main()
