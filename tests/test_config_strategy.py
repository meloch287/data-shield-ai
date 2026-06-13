"""Тесты конфигурации стратегий замены Data Shield AI (Block B).

Покрывает фокус-область:
  * Config.strategy / pseudonym_key / reversible — дефолты и заморозка датакласса;
  * load_config — чтение этих полей из временного `.datashield.json`
    (по явному пути и через ./.datashield.json), дефолты для отсутствующих полей,
    приведение типов (str/bool);
  * build_engine(config) — использует config.strategy, config.pseudonym_key,
    config.reversible; поддерживает строковый и объектный override стратегии,
    override reversible через kwarg; неизвестная стратегия → ValueError;
  * псевдонимизация: разный pseudonym_key даёт разные псевдонимы для одного и
    того же входа; одинаковый key детерминирован; одно значение в рамках запроса
    получает одну замену;
  * reversible из конфига наполняет result.vault и обеспечивает result.restore().

Все утверждения опираются на реально прочитанный исходный код datashield/*.
Только stdlib: unittest, json, tempfile, os, dataclasses.
"""
import dataclasses
import json
import os
import tempfile
import unittest

from datashield import Config, build_engine, load_config, redact
from datashield.strategies import (
    PlaceholderStrategy,
    PseudonymStrategy,
)

# Надёжно детектируемые значения: EMAIL и PHONE стабильно ловятся каталогом.
EMAIL_TEXT = "write to bob@corp.io now"
PHONE_TEXT = "call +1 415 555 0000"


def _write_temp_config(payload) -> str:
    """Создаёт временный JSON-конфиг, возвращает путь (вызывающий удаляет)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


# =============================================================================
# Config: дефолты и заморозка
# =============================================================================
class ConfigDefaultsTests(unittest.TestCase):
    def test_default_strategy_is_placeholder(self):
        self.assertEqual(Config().strategy, "placeholder")

    def test_default_pseudonym_key_is_empty_string(self):
        self.assertEqual(Config().pseudonym_key, "")

    def test_default_reversible_is_false(self):
        self.assertIs(Config().reversible, False)

    def test_config_is_frozen(self):
        cfg = Config()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.strategy = "pseudonym"  # type: ignore[misc]

    def test_explicit_fields_are_stored(self):
        cfg = Config(strategy="pseudonym", pseudonym_key="abc", reversible=True)
        self.assertEqual(cfg.strategy, "pseudonym")
        self.assertEqual(cfg.pseudonym_key, "abc")
        self.assertTrue(cfg.reversible)


# =============================================================================
# load_config: загрузка strategy/pseudonym_key/reversible из JSON
# =============================================================================
class LoadConfigStrategyTests(unittest.TestCase):
    def test_load_all_three_fields_from_explicit_path(self):
        path = _write_temp_config(
            {"strategy": "pseudonym", "pseudonym_key": "secret", "reversible": True}
        )
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        self.assertEqual(cfg.strategy, "pseudonym")
        self.assertEqual(cfg.pseudonym_key, "secret")
        self.assertTrue(cfg.reversible)

    def test_missing_fields_fall_back_to_defaults(self):
        # В JSON только strategy — pseudonym_key и reversible берутся дефолтные.
        path = _write_temp_config({"strategy": "remove"})
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        self.assertEqual(cfg.strategy, "remove")
        self.assertEqual(cfg.pseudonym_key, "")
        self.assertFalse(cfg.reversible)

    def test_empty_json_object_gives_strategy_defaults(self):
        path = _write_temp_config({})
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        self.assertEqual(cfg.strategy, "placeholder")
        self.assertEqual(cfg.pseudonym_key, "")
        self.assertFalse(cfg.reversible)

    def test_no_file_returns_defaults(self):
        # В пустой директории без ./.datashield.json — чистые дефолты.
        directory = tempfile.mkdtemp()
        previous = os.getcwd()
        os.chdir(directory)
        try:
            cfg = load_config()
        finally:
            os.chdir(previous)
        self.assertEqual(cfg.strategy, "placeholder")
        self.assertEqual(cfg.pseudonym_key, "")
        self.assertFalse(cfg.reversible)

    def test_loaded_from_cwd_default_config_name(self):
        # load_config() без пути читает ./.datashield.json.
        directory = tempfile.mkdtemp()
        config_path = os.path.join(directory, ".datashield.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(
                {"strategy": "hash", "pseudonym_key": "pk", "reversible": True},
                handle,
            )
        previous = os.getcwd()
        os.chdir(directory)
        try:
            cfg = load_config()
        finally:
            os.chdir(previous)
        self.assertEqual(cfg.strategy, "hash")
        self.assertEqual(cfg.pseudonym_key, "pk")
        self.assertTrue(cfg.reversible)

    def test_pseudonym_key_is_coerced_to_string(self):
        # В JSON число — load_config приводит str(...).
        path = _write_temp_config({"strategy": "pseudonym", "pseudonym_key": 12345})
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        self.assertEqual(cfg.pseudonym_key, "12345")
        self.assertIsInstance(cfg.pseudonym_key, str)

    def test_reversible_is_coerced_to_bool(self):
        # JSON true/false → Python bool; непустые/пустые значения → bool(...).
        path_true = _write_temp_config({"reversible": 1})
        path_false = _write_temp_config({"reversible": 0})
        try:
            cfg_true = load_config(path_true)
            cfg_false = load_config(path_false)
        finally:
            os.remove(path_true)
            os.remove(path_false)
        self.assertIs(cfg_true.reversible, True)
        self.assertIs(cfg_false.reversible, False)

    def test_strategy_is_coerced_to_string(self):
        path = _write_temp_config({"strategy": "partial"})
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        self.assertIsInstance(cfg.strategy, str)
        self.assertEqual(cfg.strategy, "partial")


# =============================================================================
# build_engine: использует config.strategy / pseudonym_key / reversible
# =============================================================================
class BuildEngineStrategyTests(unittest.TestCase):
    def test_default_config_builds_placeholder_strategy(self):
        engine = build_engine(Config())
        self.assertIsInstance(engine.strategy, PlaceholderStrategy)

    def test_config_strategy_pseudonym_is_used(self):
        engine = build_engine(Config(strategy="pseudonym", pseudonym_key="k1"))
        self.assertIsInstance(engine.strategy, PseudonymStrategy)
        self.assertEqual(engine.strategy.key, "k1")

    def test_config_pseudonym_key_propagates_to_strategy(self):
        engine = build_engine(Config(strategy="pseudonym", pseudonym_key="topsecret"))
        self.assertEqual(engine.strategy.key, "topsecret")

    def test_config_reversible_propagates_to_engine(self):
        self.assertTrue(build_engine(Config(reversible=True)).reversible)
        self.assertFalse(build_engine(Config(reversible=False)).reversible)

    def test_string_strategy_override_still_uses_config_key(self):
        # Передан strategy='pseudonym' строкой — ключ берётся из config.
        engine = build_engine(Config(pseudonym_key="kk"), strategy="pseudonym")
        self.assertIsInstance(engine.strategy, PseudonymStrategy)
        self.assertEqual(engine.strategy.key, "kk")

    def test_object_strategy_override_is_passed_through(self):
        custom = PseudonymStrategy(key="objkey")
        engine = build_engine(Config(strategy="placeholder"), strategy=custom)
        self.assertIs(engine.strategy, custom)

    def test_reversible_kwarg_overrides_config_true_to_false(self):
        engine = build_engine(Config(reversible=True), reversible=False)
        self.assertFalse(engine.reversible)

    def test_reversible_kwarg_overrides_config_false_to_true(self):
        engine = build_engine(Config(reversible=False), reversible=True)
        self.assertTrue(engine.reversible)

    def test_unknown_strategy_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            build_engine(Config(strategy="does-not-exist"))
        self.assertIn("does-not-exist", str(ctx.exception))

    def test_none_config_defaults_to_placeholder(self):
        # build_engine(None) использует Config() — стратегия placeholder.
        engine = build_engine(None)
        self.assertIsInstance(engine.strategy, PlaceholderStrategy)
        self.assertFalse(engine.reversible)


# =============================================================================
# Псевдонимизация: разный ключ → разные псевдонимы, один ключ → детерминизм
# =============================================================================
class PseudonymKeyBehaviourTests(unittest.TestCase):
    def test_different_keys_yield_different_pseudonyms_for_email(self):
        cfg_a = Config(strategy="pseudonym", pseudonym_key="AAA", reversible=True)
        cfg_b = Config(strategy="pseudonym", pseudonym_key="BBB", reversible=True)
        r_a = redact(EMAIL_TEXT, config=cfg_a)
        r_b = redact(EMAIL_TEXT, config=cfg_b)
        # Оба замаскированы (оригинала нет), но между собой отличаются.
        self.assertNotIn("bob@corp.io", r_a.masked_text)
        self.assertNotIn("bob@corp.io", r_b.masked_text)
        self.assertNotEqual(r_a.masked_text, r_b.masked_text)

    def test_different_keys_yield_different_pseudonyms_for_phone(self):
        cfg_a = Config(strategy="pseudonym", pseudonym_key="K1", reversible=True)
        cfg_b = Config(strategy="pseudonym", pseudonym_key="K2", reversible=True)
        r_a = redact(PHONE_TEXT, config=cfg_a)
        r_b = redact(PHONE_TEXT, config=cfg_b)
        self.assertNotEqual(r_a.masked_text, r_b.masked_text)

    def test_empty_key_differs_from_nonempty_key(self):
        r_empty = redact(
            PHONE_TEXT,
            config=Config(strategy="pseudonym", pseudonym_key="", reversible=True),
        )
        r_keyed = redact(
            PHONE_TEXT,
            config=Config(strategy="pseudonym", pseudonym_key="x", reversible=True),
        )
        self.assertNotEqual(r_empty.masked_text, r_keyed.masked_text)

    def test_same_key_is_deterministic_across_runs(self):
        cfg = Config(strategy="pseudonym", pseudonym_key="SAME", reversible=True)
        first = redact(PHONE_TEXT, config=cfg)
        second = redact(PHONE_TEXT, config=cfg)
        self.assertEqual(first.masked_text, second.masked_text)

    def test_repeated_value_in_one_request_gets_one_pseudonym(self):
        # Одно и то же значение в рамках запроса — одна стабильная замена.
        text = "p1 +1 415 555 0000 and p2 +1 415 555 0000"
        result = redact(
            text,
            config=Config(strategy="pseudonym", pseudonym_key="X", reversible=True),
        )
        # В vault одна запись (замена→оригинал), значит замена единственная.
        self.assertEqual(len(result.vault), 1)
        # Та же замена встречается в тексте дважды.
        (replacement,) = result.vault.keys()
        self.assertEqual(result.masked_text.count(replacement), 2)

    def test_pseudonym_email_keeps_email_shape(self):
        # Format-preserving: фейковый email содержит '@'.
        result = redact(
            EMAIL_TEXT,
            config=Config(strategy="pseudonym", pseudonym_key="k", reversible=True),
        )
        (replacement,) = result.vault.keys()
        self.assertIn("@", replacement)


# =============================================================================
# reversible из конфига наполняет result.vault и обеспечивает restore()
# =============================================================================
class ReversibleVaultTests(unittest.TestCase):
    def test_reversible_true_populates_vault_placeholder(self):
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder", reversible=True)
        )
        self.assertEqual(result.vault, {"[EMAIL_1]": "bob@corp.io"})

    def test_reversible_false_leaves_vault_empty(self):
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder", reversible=False)
        )
        self.assertEqual(result.vault, {})

    def test_default_config_vault_is_empty(self):
        # Дефолтный Config: reversible=False → vault пуст.
        result = redact(EMAIL_TEXT, config=Config())
        self.assertEqual(result.vault, {})

    def test_restore_round_trips_placeholder(self):
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder", reversible=True)
        )
        self.assertEqual(result.restore(), EMAIL_TEXT)

    def test_restore_round_trips_pseudonym(self):
        result = redact(
            EMAIL_TEXT,
            config=Config(strategy="pseudonym", pseudonym_key="kp", reversible=True),
        )
        # Оригинала в маске нет, но restore по vault его возвращает.
        self.assertNotIn("bob@corp.io", result.masked_text)
        self.assertEqual(result.restore(), EMAIL_TEXT)

    def test_restore_round_trips_hash(self):
        result = redact(
            EMAIL_TEXT, config=Config(strategy="hash", reversible=True)
        )
        self.assertNotIn("bob@corp.io", result.masked_text)
        self.assertEqual(result.restore(), EMAIL_TEXT)

    def test_restore_on_external_text_uses_vault(self):
        # result.restore(text) применяет vault к произвольному тексту.
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder", reversible=True)
        )
        external = "ping [EMAIL_1] twice [EMAIL_1]"
        self.assertEqual(
            result.restore(external), "ping bob@corp.io twice bob@corp.io"
        )

    def test_vault_maps_replacement_to_original(self):
        # Ключ vault — замена, значение — оригинал (направление важно для restore).
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder", reversible=True)
        )
        self.assertIn("bob@corp.io", result.vault.values())
        self.assertNotIn("bob@corp.io", result.vault.keys())

    def test_reversible_via_build_engine_kwarg_populates_vault(self):
        # reversible можно включить и kwarg'ом build_engine, минуя config.
        result = redact(
            EMAIL_TEXT, config=Config(strategy="placeholder"), reversible=True
        )
        self.assertEqual(result.vault, {"[EMAIL_1]": "bob@corp.io"})

    def test_no_findings_means_empty_vault_even_when_reversible(self):
        # Нет конфиденциальных данных → нечего класть в vault.
        result = redact(
            "ничего секретного здесь нет",
            config=Config(strategy="placeholder", reversible=True),
        )
        self.assertEqual(result.findings, [])
        self.assertEqual(result.vault, {})


# =============================================================================
# Сквозной сценарий: конфиг из JSON → build_engine → redact → restore
# =============================================================================
class EndToEndConfigFileTests(unittest.TestCase):
    def test_json_config_drives_reversible_pseudonym_pipeline(self):
        path = _write_temp_config(
            {"strategy": "pseudonym", "pseudonym_key": "file-key", "reversible": True}
        )
        try:
            cfg = load_config(path)
        finally:
            os.remove(path)
        engine = build_engine(cfg)
        self.assertIsInstance(engine.strategy, PseudonymStrategy)
        self.assertEqual(engine.strategy.key, "file-key")
        self.assertTrue(engine.reversible)

        result = engine.redact(EMAIL_TEXT)
        self.assertNotIn("bob@corp.io", result.masked_text)
        self.assertTrue(result.vault)
        self.assertEqual(result.restore(), EMAIL_TEXT)

    def test_two_config_files_with_distinct_keys_diverge(self):
        path_a = _write_temp_config(
            {"strategy": "pseudonym", "pseudonym_key": "alpha", "reversible": True}
        )
        path_b = _write_temp_config(
            {"strategy": "pseudonym", "pseudonym_key": "beta", "reversible": True}
        )
        try:
            cfg_a = load_config(path_a)
            cfg_b = load_config(path_b)
        finally:
            os.remove(path_a)
            os.remove(path_b)
        r_a = build_engine(cfg_a).redact(PHONE_TEXT)
        r_b = build_engine(cfg_b).redact(PHONE_TEXT)
        self.assertNotEqual(r_a.masked_text, r_b.masked_text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
