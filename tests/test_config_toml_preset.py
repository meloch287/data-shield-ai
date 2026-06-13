"""Тесты конфигурации Block D: TOML, пресеты, min_severity.

Покрывает реально прочитанный исходный код:
  * datashield/config.py — Config.preset / Config.min_severity (дефолты),
    load_config из JSON (включая новые поля), load_config из .datashield.toml
    (через stdlib tomllib на Python 3.11+; на <3.11 — ValueError про 3.11),
    find_default_config (предпочитает .json, затем .toml), не-dict → ValueError;
  * datashield/api.py build_engine — учитывает config.preset (даёт only) и
    config.min_severity (даёт min_severity_rank), пресет minimal задаёт порог
    уверенности, явные only / min_confidence перекрывают пресет;
  * datashield/presets.py resolve_preset — неизвестный пресет → ValueError.

Всё опирается на фактическое поведение, а не на предположения.
Только stdlib: unittest, json, os, sys, tempfile.
"""
import json
import os
import sys
import tempfile
import unittest

from datashield import Config, build_engine, load_config
from datashield.config import (
    DEFAULT_CONFIG_NAME,
    DEFAULT_CONFIG_NAMES,
    find_default_config,
)
from datashield.presets import PRESETS, resolve_preset
from datashield.taxonomy import SEVERITY_ORDER, severity_of, types_in_categories

HAS_TOMLLIB = sys.version_info >= (3, 11)


def _write(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# =============================================================================
# Config: новые поля и их дефолты
# =============================================================================
class ConfigDefaultsTests(unittest.TestCase):
    def test_preset_and_min_severity_default_empty(self):
        cfg = Config()
        self.assertEqual(cfg.preset, "")
        self.assertEqual(cfg.min_severity, "")

    def test_existing_defaults_unchanged(self):
        cfg = Config()
        self.assertEqual(cfg.min_confidence, 0.7)
        self.assertEqual(cfg.placeholder_template, "[{type}_{n}]")
        self.assertEqual(cfg.strategy, "placeholder")
        self.assertFalse(cfg.reversible)

    def test_config_is_frozen(self):
        # dataclass(frozen=True): присваивание полю запрещено.
        import dataclasses

        cfg = Config()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.preset = "hipaa"  # type: ignore[misc]

    def test_default_config_name_constants(self):
        self.assertEqual(DEFAULT_CONFIG_NAME, ".datashield.json")
        # find_default_config проверяет именно .json, затем .toml.
        self.assertEqual(
            DEFAULT_CONFIG_NAMES, (".datashield.json", ".datashield.toml")
        )


# =============================================================================
# load_config из JSON: новые поля preset / min_severity
# =============================================================================
class LoadConfigJsonTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_json_reads_preset_and_min_severity(self):
        path = _write(
            self.dir,
            "cfg.json",
            json.dumps(
                {
                    "preset": "pci-dss",
                    "min_severity": "high",
                    "min_confidence": 0.8,
                }
            ),
        )
        cfg = load_config(path)
        self.assertEqual(cfg.preset, "pci-dss")
        self.assertEqual(cfg.min_severity, "high")
        self.assertEqual(cfg.min_confidence, 0.8)

    def test_json_missing_new_fields_default_empty(self):
        # Старый конфиг без новых ключей: дефолты — пустые строки.
        path = _write(self.dir, "old.json", json.dumps({"min_confidence": 0.5}))
        cfg = load_config(path)
        self.assertEqual(cfg.preset, "")
        self.assertEqual(cfg.min_severity, "")
        self.assertEqual(cfg.min_confidence, 0.5)

    def test_json_coerces_preset_to_str(self):
        # str(...) применяется к значению preset.
        path = _write(self.dir, "num.json", json.dumps({"preset": 123}))
        cfg = load_config(path)
        self.assertEqual(cfg.preset, "123")

    def test_non_dict_json_raises_value_error(self):
        path = _write(self.dir, "list.json", json.dumps([1, 2, 3]))
        with self.assertRaises(ValueError):
            load_config(path)

    def test_no_config_returns_defaults(self):
        # Путь не задан и в cwd нет конфига — но в произвольной несуществующей
        # директории load_config(path) на реальный файл всё равно нужен.
        # Здесь проверяем форму вызова без файла: пустой каталог + явный None.
        empty = tempfile.mkdtemp()
        self.assertIsNone(find_default_config(empty))


# =============================================================================
# load_config из TOML (stdlib tomllib только на 3.11+)
# =============================================================================
class LoadConfigTomlTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    @unittest.skipIf(not HAS_TOMLLIB, "tomllib доступен только на Python 3.11+")
    def test_toml_reads_all_fields(self):
        path = _write(
            self.dir,
            "a.datashield.toml",
            "\n".join(
                [
                    'min_confidence = 0.85',
                    'preset = "hipaa"',
                    'min_severity = "high"',
                    'strategy = "hash"',
                    'disabled_detectors = ["EMAIL", "PHONE"]',
                ]
            )
            + "\n",
        )
        cfg = load_config(path)
        self.assertEqual(cfg.min_confidence, 0.85)
        self.assertEqual(cfg.preset, "hipaa")
        self.assertEqual(cfg.min_severity, "high")
        self.assertEqual(cfg.strategy, "hash")
        self.assertEqual(cfg.disabled_detectors, ("EMAIL", "PHONE"))

    @unittest.skipIf(not HAS_TOMLLIB, "tomllib доступен только на Python 3.11+")
    def test_toml_empty_file_gives_defaults(self):
        # Пустой TOML — валидная пустая таблица; все поля дефолтные.
        path = _write(self.dir, "empty.datashield.toml", "")
        cfg = load_config(path)
        self.assertEqual(cfg.preset, "")
        self.assertEqual(cfg.min_severity, "")
        self.assertEqual(cfg.min_confidence, 0.7)

    @unittest.skipIf(HAS_TOMLLIB, "проверка пути для Python < 3.11")
    def test_toml_without_tomllib_raises_value_error_mentioning_311(self):
        path = _write(self.dir, "x.datashield.toml", 'preset = "gdpr"\n')
        with self.assertRaises(ValueError) as ctx:
            load_config(path)
        self.assertIn("3.11", str(ctx.exception))


# =============================================================================
# find_default_config: предпочтение .json перед .toml
# =============================================================================
class FindDefaultConfigTests(unittest.TestCase):
    def test_returns_none_in_empty_dir(self):
        self.assertIsNone(find_default_config(tempfile.mkdtemp()))

    def test_finds_json(self):
        d = tempfile.mkdtemp()
        _write(d, ".datashield.json", "{}")
        found = find_default_config(d)
        self.assertEqual(os.path.basename(found), ".datashield.json")

    def test_finds_toml_when_only_toml(self):
        d = tempfile.mkdtemp()
        _write(d, ".datashield.toml", 'preset = "gdpr"\n')
        found = find_default_config(d)
        self.assertEqual(os.path.basename(found), ".datashield.toml")

    def test_prefers_json_over_toml_when_both(self):
        d = tempfile.mkdtemp()
        _write(d, ".datashield.toml", 'preset = "gdpr"\n')
        _write(d, ".datashield.json", '{"preset": "pci-dss"}')
        found = find_default_config(d)
        self.assertEqual(os.path.basename(found), ".datashield.json")

    def test_found_path_is_absolute_and_in_dir(self):
        d = tempfile.mkdtemp()
        _write(d, ".datashield.json", "{}")
        found = find_default_config(d)
        self.assertTrue(os.path.isfile(found))
        self.assertEqual(os.path.dirname(found), d)


# =============================================================================
# resolve_preset (реальное поведение пресетов)
# =============================================================================
class ResolvePresetTests(unittest.TestCase):
    def test_known_presets_listed(self):
        for name in ("pci-dss", "hipaa", "gdpr", "secrets-only", "ru-gov", "minimal"):
            self.assertIn(name, PRESETS)

    def test_unknown_preset_raises_value_error(self):
        with self.assertRaises(ValueError):
            resolve_preset("does-not-exist")

    def test_secrets_only_resolves_to_secret_types(self):
        res = resolve_preset("secrets-only")
        self.assertIsNotNone(res.only)
        # секреты входят, контактные типы — нет.
        self.assertIn("AWS_ACCESS_KEY", res.only)
        self.assertNotIn("EMAIL", res.only)
        self.assertIsNone(res.min_confidence)

    def test_minimal_sets_min_confidence_no_only(self):
        res = resolve_preset("minimal")
        self.assertIsNone(res.only)
        self.assertEqual(res.min_confidence, 0.9)

    def test_pci_dss_covers_financial_and_secret(self):
        res = resolve_preset("pci-dss")
        expected = types_in_categories(["financial", "secret"])
        self.assertEqual(res.only, expected)
        self.assertIn("CREDIT_CARD", res.only)


# =============================================================================
# build_engine учитывает config.preset и config.min_severity
# =============================================================================
class BuildEnginePresetTests(unittest.TestCase):
    def test_config_preset_sets_only(self):
        eng = build_engine(Config(preset="secrets-only"))
        self.assertIsNotNone(eng.only)
        self.assertIn("AWS_ACCESS_KEY", eng.only)
        self.assertNotIn("EMAIL", eng.only)

    def test_config_minimal_preset_sets_min_confidence(self):
        eng = build_engine(Config(preset="minimal"))
        self.assertEqual(eng.min_confidence, 0.9)

    def test_no_preset_leaves_only_none(self):
        eng = build_engine(Config())
        self.assertIsNone(eng.only)

    def test_explicit_only_overrides_preset(self):
        # Явный only имеет приоритет над набором типов пресета.
        eng = build_engine(Config(preset="secrets-only"), only=["EMAIL"])
        self.assertEqual(eng.only, {"EMAIL"})

    def test_explicit_min_confidence_overrides_preset(self):
        # Явный min_confidence перекрывает порог пресета minimal (0.9).
        eng = build_engine(Config(preset="minimal"), min_confidence=0.5)
        self.assertEqual(eng.min_confidence, 0.5)

    def test_unknown_config_preset_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_engine(Config(preset="nope"))


class BuildEngineMinSeverityTests(unittest.TestCase):
    def test_config_min_severity_sets_rank(self):
        eng = build_engine(Config(min_severity="high"))
        self.assertEqual(eng.min_severity_rank, SEVERITY_ORDER["high"])

    def test_empty_min_severity_disables_filter(self):
        eng = build_engine(Config())
        # пустое значение → ранг -1 (фильтр выключен).
        self.assertEqual(eng.min_severity_rank, -1)

    def test_explicit_min_severity_overrides_config(self):
        eng = build_engine(Config(min_severity="low"), min_severity="critical")
        self.assertEqual(eng.min_severity_rank, SEVERITY_ORDER["critical"])

    def test_min_severity_high_filters_out_low_findings(self):
        # IP — network/low; при min_severity=high он отсеивается, секрет остаётся.
        text = "ключ AWS AKIAIOSFODNN7EXAMPLE и адрес 192.168.0.1"
        eng = build_engine(Config(min_severity="high"))
        types = {f.type for f in eng.analyze(text)}
        # все оставшиеся находки имеют severity >= high
        for t in types:
            self.assertGreaterEqual(
                SEVERITY_ORDER[severity_of(t)], SEVERITY_ORDER["high"]
            )
        self.assertNotIn("IP", types)


# =============================================================================
# Интеграция config → load_config → build_engine
# =============================================================================
class ConfigToEngineIntegrationTests(unittest.TestCase):
    def test_loaded_json_preset_flows_into_engine(self):
        d = tempfile.mkdtemp()
        path = _write(d, "cfg.json", json.dumps({"preset": "secrets-only"}))
        cfg = load_config(path)
        eng = build_engine(cfg)
        self.assertIn("AWS_ACCESS_KEY", eng.only)
        self.assertNotIn("EMAIL", eng.only)

    @unittest.skipIf(not HAS_TOMLLIB, "tomllib доступен только на Python 3.11+")
    def test_loaded_toml_min_severity_flows_into_engine(self):
        d = tempfile.mkdtemp()
        path = _write(
            d, "cfg.datashield.toml", 'min_severity = "critical"\n'
        )
        cfg = load_config(path)
        eng = build_engine(cfg)
        self.assertEqual(eng.min_severity_rank, SEVERITY_ORDER["critical"])


if __name__ == "__main__":
    unittest.main()
