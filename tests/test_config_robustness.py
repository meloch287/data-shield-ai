"""Тесты устойчивости конфигурации (Block E) для Data Shield AI.

Покрывает реально прочитанный исходный код:
  * datashield/config.py — Config.normalize / Config.fold_homoglyphs /
    Config.max_input_size: дефолты (False / False / 0), загрузка из
    .datashield.json и (на Python 3.11+) из .datashield.toml, корректные типы;
  * datashield/api.py build_engine — пробрасывает поля конфига в движок,
    явные аргументы (normalize / fold_homoglyphs / max_input_size) перекрывают
    конфиг (включая отключение лимита явным 0);
  * datashield/engine.py — _prepare: max_input_size>0 даёт ValueError, когда
    len(text) превышает лимит (срабатывает и в analyze, и в redact);
    normalize=True нормализует ввод ДО детекции, маскированный вывод — в
    нормализованном пространстве;
  * datashield/normalize.py — nfkc / fold_homoglyphs / normalize_text.

ВАЖНО про полноширинные цифры: спецификация задачи утверждала, что без
normalize полноширинная карта «４１１１ …» НЕ детектируется. Реальный исходный
код детектирует её и БЕЗ normalize, потому что регэксп карты использует ``\\d``
(Unicode-цифры), а валидатор Луна опирается на ``re.sub(r"\\D", ...)`` и
``int(ch)`` — оба корректно работают на полноширинных цифрах. Поэтому тесты
утверждают ФАКТИЧЕСКОЕ поведение: без normalize находка существует, но её
значение — полноширинная строка; с normalize находка та же, но значение уже в
ASCII-пространстве (４→4). См. test_*fullwidth*.

Всё опирается на фактическое поведение, а не на предположения.
Только stdlib: unittest, json, os, sys, tempfile.
"""
import json
import os
import sys
import tempfile
import unittest

from datashield import Config, build_engine, load_config, normalize_text
from datashield.config import find_default_config
from datashield.normalize import fold_homoglyphs, nfkc

HAS_TOMLLIB = sys.version_info >= (3, 11)

# Полноширинная версия валидного по Луну номера карты 4111 1111 1111 1111.
_ASCII_CARD = "4111 1111 1111 1111"
_FULLWIDTH_CARD = "".join(
    chr(ord(ch) + 0xFEE0) if "0" <= ch <= "9" else ch for ch in _ASCII_CARD
)


def _write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# ---------------------------------------------------------------------------
# Config: дефолты новых полей
# ---------------------------------------------------------------------------
class ConfigDefaultsTest(unittest.TestCase):
    def test_defaults_normalize_false(self):
        self.assertIs(Config().normalize, False)

    def test_defaults_fold_homoglyphs_false(self):
        self.assertIs(Config().fold_homoglyphs, False)

    def test_defaults_max_input_size_zero(self):
        self.assertEqual(Config().max_input_size, 0)

    def test_default_max_input_size_is_int(self):
        self.assertIsInstance(Config().max_input_size, int)


# ---------------------------------------------------------------------------
# load_config: чтение новых полей из JSON
# ---------------------------------------------------------------------------
class LoadConfigJsonTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_json_reads_all_three_fields(self):
        path = _write(
            self.dir,
            "full.datashield.json",
            json.dumps(
                {"normalize": True, "fold_homoglyphs": True, "max_input_size": 100}
            ),
        )
        cfg = load_config(path)
        self.assertIs(cfg.normalize, True)
        self.assertIs(cfg.fold_homoglyphs, True)
        self.assertEqual(cfg.max_input_size, 100)
        self.assertIsInstance(cfg.max_input_size, int)

    def test_json_missing_fields_fall_back_to_defaults(self):
        path = _write(self.dir, "partial.datashield.json", json.dumps({}))
        cfg = load_config(path)
        self.assertIs(cfg.normalize, False)
        self.assertIs(cfg.fold_homoglyphs, False)
        self.assertEqual(cfg.max_input_size, 0)

    def test_json_max_input_size_coerced_to_int(self):
        # load_config оборачивает значение в int(...) — строка "42" становится 42.
        path = _write(
            self.dir, "str.datashield.json", json.dumps({"max_input_size": "42"})
        )
        cfg = load_config(path)
        self.assertEqual(cfg.max_input_size, 42)
        self.assertIsInstance(cfg.max_input_size, int)

    def test_find_default_config_picks_up_json_in_dir(self):
        _write(self.dir, ".datashield.json", json.dumps({"normalize": True}))
        found = find_default_config(self.dir)
        self.assertIsNotNone(found)
        self.assertTrue(found.endswith(".datashield.json"))
        self.assertIs(load_config(found).normalize, True)


# ---------------------------------------------------------------------------
# load_config: чтение из TOML (stdlib tomllib только на Python 3.11+)
# ---------------------------------------------------------------------------
class LoadConfigTomlTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    @unittest.skipIf(not HAS_TOMLLIB, "tomllib доступен только на Python 3.11+")
    def test_toml_reads_all_three_fields(self):
        path = _write(
            self.dir,
            "full.datashield.toml",
            "normalize = true\n"
            "fold_homoglyphs = true\n"
            "max_input_size = 50\n",
        )
        cfg = load_config(path)
        self.assertIs(cfg.normalize, True)
        self.assertIs(cfg.fold_homoglyphs, True)
        self.assertEqual(cfg.max_input_size, 50)

    @unittest.skipIf(not HAS_TOMLLIB, "tomllib доступен только на Python 3.11+")
    def test_toml_partial_uses_defaults(self):
        path = _write(self.dir, "partial.datashield.toml", "normalize = true\n")
        cfg = load_config(path)
        self.assertIs(cfg.normalize, True)
        self.assertIs(cfg.fold_homoglyphs, False)
        self.assertEqual(cfg.max_input_size, 0)

    @unittest.skipIf(HAS_TOMLLIB, "проверка пути для Python < 3.11")
    def test_toml_without_tomllib_raises_value_error(self):
        path = _write(self.dir, "x.datashield.toml", "normalize = true\n")
        with self.assertRaises(ValueError):
            load_config(path)


# ---------------------------------------------------------------------------
# normalize.py — низкоуровневые помощники
# ---------------------------------------------------------------------------
class NormalizeHelpersTest(unittest.TestCase):
    def test_nfkc_folds_fullwidth_digits(self):
        self.assertEqual(nfkc("４１１１"), "4111")

    def test_normalize_text_default_does_not_fold_homoglyphs(self):
        # homoglyphs=False по умолчанию: смешанный токен не сворачивается.
        self.assertEqual(normalize_text("pаypal"), "pаypal")

    def test_normalize_text_homoglyphs_folds_mixed_token(self):
        self.assertEqual(normalize_text("pаypal", homoglyphs=True), "paypal")

    def test_fold_homoglyphs_leaves_pure_russian_untouched(self):
        # Чисто кириллический токен без латиницы не трогается.
        self.assertEqual(fold_homoglyphs("оптимизация"), "оптимизация")

    def test_fold_homoglyphs_leaves_pure_latin_untouched(self):
        self.assertEqual(fold_homoglyphs("paypal"), "paypal")


# ---------------------------------------------------------------------------
# build_engine: проброс полей конфига в движок
# ---------------------------------------------------------------------------
class BuildEngineConfigApplyTest(unittest.TestCase):
    def test_config_normalize_true_sets_engine_flag(self):
        self.assertIs(build_engine(Config(normalize=True)).normalize, True)

    def test_config_fold_homoglyphs_true_sets_engine_flag(self):
        eng = build_engine(Config(fold_homoglyphs=True))
        self.assertIs(eng.fold_homoglyphs, True)

    def test_config_max_input_size_sets_engine_field(self):
        self.assertEqual(build_engine(Config(max_input_size=7)).max_input_size, 7)

    def test_default_engine_flags_are_off(self):
        eng = build_engine(Config())
        self.assertIs(eng.normalize, False)
        self.assertIs(eng.fold_homoglyphs, False)
        self.assertEqual(eng.max_input_size, 0)


# ---------------------------------------------------------------------------
# build_engine: явные аргументы перекрывают конфиг
# ---------------------------------------------------------------------------
class BuildEngineOverrideTest(unittest.TestCase):
    def test_explicit_normalize_false_overrides_config_true(self):
        eng = build_engine(Config(normalize=True), normalize=False)
        self.assertIs(eng.normalize, False)

    def test_explicit_normalize_true_overrides_config_false(self):
        eng = build_engine(Config(normalize=False), normalize=True)
        self.assertIs(eng.normalize, True)

    def test_explicit_fold_homoglyphs_overrides_config(self):
        eng = build_engine(Config(fold_homoglyphs=False), fold_homoglyphs=True)
        self.assertIs(eng.fold_homoglyphs, True)

    def test_explicit_max_input_size_overrides_config(self):
        eng = build_engine(Config(max_input_size=0), max_input_size=3)
        self.assertEqual(eng.max_input_size, 3)

    def test_explicit_zero_disables_config_limit(self):
        # Явный 0 перекрывает ненулевой лимит конфига (config is None? -> override).
        eng = build_engine(Config(max_input_size=9), max_input_size=0)
        self.assertEqual(eng.max_input_size, 0)


# ---------------------------------------------------------------------------
# max_input_size: ValueError в analyze и redact
# ---------------------------------------------------------------------------
class MaxInputSizeEnforcementTest(unittest.TestCase):
    def test_analyze_raises_when_over_limit(self):
        eng = build_engine(Config(max_input_size=5))
        with self.assertRaises(ValueError):
            eng.analyze("123456")  # длина 6 > 5

    def test_redact_raises_when_over_limit(self):
        eng = build_engine(Config(max_input_size=5))
        with self.assertRaises(ValueError):
            eng.redact("123456")

    def test_error_message_mentions_actual_length_and_limit(self):
        eng = build_engine(Config(max_input_size=5))
        with self.assertRaises(ValueError) as ctx:
            eng.analyze("123456")
        message = str(ctx.exception)
        self.assertIn("6", message)
        self.assertIn("5", message)

    def test_exactly_at_limit_is_allowed(self):
        eng = build_engine(Config(max_input_size=5))
        # Длина ровно 5 не превышает лимит (строгое >), ошибки нет.
        self.assertEqual(eng.analyze("12345"), [])

    def test_zero_limit_disables_check(self):
        eng = build_engine(Config(max_input_size=0))
        # Лимит 0 (falsy) — проверка не выполняется, любой длины ввод проходит.
        self.assertEqual(eng.analyze("a" * 1000), [])

    def test_explicit_limit_enforced_over_config_zero(self):
        eng = build_engine(Config(max_input_size=0), max_input_size=3)
        with self.assertRaises(ValueError):
            eng.analyze("toolong")


# ---------------------------------------------------------------------------
# normalize=True: эффект на детекцию полноширинных цифр (ФАКТИЧЕСКОЕ поведение)
# ---------------------------------------------------------------------------
class FullwidthCardNormalizationTest(unittest.TestCase):
    def test_sanity_ascii_card_detected(self):
        findings = build_engine(Config()).analyze("Карта: " + _ASCII_CARD)
        types = [f.type for f in findings]
        self.assertIn("CREDIT_CARD", types)

    def test_fullwidth_card_detected_even_without_normalize(self):
        # ФАКТ: регэксп карты использует \\d (Unicode-цифры), а валидатор Луна
        # опирается на re.sub(\\D) и int(ch) — оба работают на полноширинных
        # цифрах. Поэтому карта детектируется и без normalize.
        findings = build_engine(Config()).analyze("Карта: " + _FULLWIDTH_CARD)
        cards = [f for f in findings if f.type == "CREDIT_CARD"]
        self.assertEqual(len(cards), 1)
        # Без нормализации значение находки — полноширинная строка как есть.
        self.assertEqual(cards[0].value, _FULLWIDTH_CARD)

    def test_normalize_yields_ascii_value_in_finding(self):
        # С normalize ввод нормализуется ДО детекции: значение находки уже ASCII.
        findings = build_engine(Config(normalize=True)).analyze(
            "Карта: " + _FULLWIDTH_CARD
        )
        cards = [f for f in findings if f.type == "CREDIT_CARD"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].value, _ASCII_CARD)

    def test_normalize_via_explicit_arg_matches_config(self):
        via_config = build_engine(Config(normalize=True)).analyze(
            "Карта: " + _FULLWIDTH_CARD
        )
        via_arg = build_engine(Config(), normalize=True).analyze(
            "Карта: " + _FULLWIDTH_CARD
        )
        self.assertEqual(
            [(f.type, f.value) for f in via_config],
            [(f.type, f.value) for f in via_arg],
        )

    def test_redact_masks_fullwidth_card_in_normalized_space(self):
        # При normalize=True redact режет ту же нормализованную строку: вывод —
        # в нормализованном пространстве, полноширинных цифр в нём не остаётся.
        result = build_engine(Config(normalize=True)).redact(
            "Карта: " + _FULLWIDTH_CARD
        )
        self.assertNotIn(_FULLWIDTH_CARD, result.masked_text)
        # Полноширинная цифра '４' не должна просочиться в маскированный вывод.
        self.assertNotIn("４", result.masked_text)
        self.assertIn("CREDIT_CARD", result.stats)


if __name__ == "__main__":
    unittest.main()
