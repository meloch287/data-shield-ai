"""Продвинутые тесты конфигурации Data Shield AI.

Покрывает:
  * custom_patterns (свой регэксп ловится; group, ignore_case, дефолтный тип);
  * disabled_detectors (выключение по имени детектора И по типу);
  * enabled_detectors (включение опциональных high_entropy / names_aggressive,
    а также приоритет enabled над disabled);
  * allowlist (домен-подстрока и точное значение пропускаются);
  * placeholder_template (кастомный формат плейсхолдеров);
  * load_config (чтение из временного JSON-файла, дефолты, невалидный JSON).

Все кейсы опираются на реально прочитанный исходный код datashield/*,
а не на догадки. Используется только stdlib (unittest, json, tempfile, os).
"""
import json
import os
import tempfile
import unittest

from datashield import Config, build_engine, load_config, redact, scan
from datashield.detectors.registry import build_active, build_catalog


# --- вспомогательное: создать временный конфиг-файл и вернуть путь -------------
def _write_temp_config(payload) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


# =============================================================================
# custom_patterns
# =============================================================================
class CustomPatternsTests(unittest.TestCase):
    def test_custom_pattern_is_caught(self):
        # Свой регэксп для номера тикета ловится и маскируется.
        cfg = Config(
            custom_patterns=(
                {"name": "ticket", "type": "TICKET", "pattern": r"TK-\d{4}",
                 "confidence": 0.95},
            )
        )
        result = redact("смотри тикет TK-1234 сегодня", config=cfg)
        self.assertEqual(result.masked_text, "смотри тикет [TICKET_1] сегодня")
        self.assertNotIn("TK-1234", result.masked_text)

    def test_custom_pattern_type_appears_in_findings(self):
        cfg = Config(
            custom_patterns=(
                {"name": "ticket", "type": "TICKET", "pattern": r"TK-\d{4}",
                 "confidence": 0.95},
            )
        )
        findings = scan("TK-9999", config=cfg)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "TICKET")
        self.assertEqual(findings[0].detector, "ticket")
        self.assertEqual(findings[0].value, "TK-9999")

    def test_custom_pattern_default_type_is_name_upper(self):
        # Если type не задан — берётся name.upper() (см. registry._custom_detectors).
        cfg = Config(
            custom_patterns=(
                {"name": "order_id", "pattern": r"ORD-\d+", "confidence": 0.95},
            )
        )
        result = redact("ссылка ORD-99 готово", config=cfg)
        self.assertIn("[ORDER_ID_1]", result.masked_text)
        self.assertEqual([f.type for f in result.findings], ["ORDER_ID"])

    def test_custom_pattern_group_masks_only_group(self):
        # group=1 — маскируется только захваченная группа, ключ остаётся.
        cfg = Config(
            custom_patterns=(
                {"name": "token_kv", "type": "MYTOK",
                 "pattern": r"mytoken=([A-Za-z0-9]+)", "group": 1,
                 "confidence": 0.95},
            )
        )
        result = redact("config mytoken=abc123 done", config=cfg)
        self.assertEqual(result.masked_text, "config mytoken=[MYTOK_1] done")

    def test_custom_pattern_ignore_case(self):
        # ignore_case=True добавляет re.IGNORECASE.
        cfg = Config(
            custom_patterns=(
                {"name": "flag", "type": "FLAG", "pattern": r"secret-flag",
                 "confidence": 0.95, "ignore_case": True},
            )
        )
        result = redact("тут A SECRET-FLAG здесь", config=cfg)
        self.assertIn("[FLAG_1]", result.masked_text)
        self.assertNotIn("SECRET-FLAG", result.masked_text)

    def test_custom_pattern_case_sensitive_by_default(self):
        # Без ignore_case регистр учитывается — верхний регистр не матчится.
        cfg = Config(
            custom_patterns=(
                {"name": "flag", "type": "FLAG", "pattern": r"secret-flag",
                 "confidence": 0.95},
            )
        )
        result = redact("тут SECRET-FLAG здесь", config=cfg)
        self.assertIn("SECRET-FLAG", result.masked_text)
        self.assertEqual(result.findings, [])

    def test_custom_pattern_default_confidence_is_high(self):
        # confidence по умолчанию 0.9 — выше дефолтного порога 0.7, значит ловится.
        cfg = Config(
            custom_patterns=(
                {"name": "code", "type": "CODE", "pattern": r"CD\d+"},
            )
        )
        findings = scan("CD42", config=cfg)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].confidence, 0.9)

    def test_custom_pattern_below_threshold_filtered(self):
        # Низкая уверенность custom-детектора отсекается порогом по умолчанию.
        cfg = Config(
            custom_patterns=(
                {"name": "lowc", "type": "LOWC", "pattern": r"LC-\d+",
                 "confidence": 0.5},
            )
        )
        self.assertNotIn("[LOWC_1]", redact("val LC-7 end", config=cfg).masked_text)

    def test_custom_pattern_below_threshold_caught_with_lower_min(self):
        # Тот же паттерн ловится, если опустить порог через min_confidence.
        cfg = Config(
            custom_patterns=(
                {"name": "lowc", "type": "LOWC", "pattern": r"LC-\d+",
                 "confidence": 0.5},
            )
        )
        result = redact("val LC-7 end", config=cfg, min_confidence=0.4)
        self.assertIn("[LOWC_1]", result.masked_text)

    def test_multiple_custom_patterns(self):
        cfg = Config(
            custom_patterns=(
                {"name": "ticket", "type": "TICKET", "pattern": r"TK-\d+",
                 "confidence": 0.95},
                {"name": "badge", "type": "BADGE", "pattern": r"BG-\d+",
                 "confidence": 0.95},
            )
        )
        result = redact("TK-1 и BG-2", config=cfg)
        self.assertIn("[TICKET_1]", result.masked_text)
        self.assertIn("[BADGE_1]", result.masked_text)

    def test_custom_pattern_does_not_break_builtin_detectors(self):
        # Кастомный паттерн соседствует со встроенным EMAIL — оба работают.
        cfg = Config(
            custom_patterns=(
                {"name": "ticket", "type": "TICKET", "pattern": r"TK-\d+",
                 "confidence": 0.95},
            )
        )
        result = redact("a@b.com по тикету TK-5", config=cfg)
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[TICKET_1]", result.masked_text)


# =============================================================================
# disabled_detectors
# =============================================================================
class DisabledDetectorsTests(unittest.TestCase):
    def test_disable_by_detector_name(self):
        # 'email' — это имя детектора (см. regex_intl.build()).
        cfg = Config(disabled_detectors=("email",))
        result = redact("пиши на a@b.com", config=cfg)
        self.assertEqual(result.masked_text, "пиши на a@b.com")

    def test_disable_by_type(self):
        # 'EMAIL' — это тип. Выключение по типу тоже работает.
        cfg = Config(disabled_detectors=("EMAIL",))
        result = redact("пиши на a@b.com", config=cfg)
        self.assertEqual(result.masked_text, "пиши на a@b.com")

    def test_disable_by_type_affects_all_detectors_of_type(self):
        # Тип IP даёт сразу ipv4 и ipv6 — выключение по типу гасит оба.
        cfg = Config(disabled_detectors=("IP",))
        active_names = {d.name for d in build_active(cfg)}
        self.assertNotIn("ipv4", active_names)
        self.assertNotIn("ipv6", active_names)
        self.assertEqual(scan("host 8.8.8.8 и ::1 тут", config=cfg), [])

    def test_disable_one_does_not_disable_others(self):
        # Выключив email, IP по-прежнему ловится.
        cfg = Config(disabled_detectors=("email",))
        found = {f.type for f in scan("a@b.com и 192.168.0.1", config=cfg)}
        self.assertNotIn("EMAIL", found)
        self.assertIn("IP", found)

    def test_disable_unknown_name_is_noop(self):
        # Неизвестное имя в disabled — ничего не ломает, email всё ещё ловится.
        cfg = Config(disabled_detectors=("does_not_exist",))
        self.assertIn("[EMAIL_1]", redact("a@b.com", config=cfg).masked_text)

    def test_disable_multiple(self):
        cfg = Config(disabled_detectors=("EMAIL", "IP"))
        result = redact("a@b.com и 192.168.0.1", config=cfg)
        self.assertNotIn("[EMAIL_1]", result.masked_text)
        self.assertNotIn("[IP_1]", result.masked_text)
        self.assertIn("a@b.com", result.masked_text)
        self.assertIn("192.168.0.1", result.masked_text)

    def test_disabled_detector_absent_in_active_catalog(self):
        cfg = Config(disabled_detectors=("email",))
        infos = [i for i in build_catalog(cfg) if i.detector.name == "email"]
        self.assertEqual(len(infos), 1)
        self.assertFalse(infos[0].enabled)


# =============================================================================
# enabled_detectors (опциональные детекторы)
# =============================================================================
class EnabledDetectorsTests(unittest.TestCase):
    HIGH_ENTROPY_VALUE = "Xk7Lm2Qp9Rt4Vw8Zb3Nc6Hd1"  # энтропия > 4.0, длина >= 20

    def test_high_entropy_off_by_default(self):
        # high_entropy выключен по умолчанию — случайная строка не маскируется.
        self.assertEqual(scan("key " + self.HIGH_ENTROPY_VALUE), [])

    def test_high_entropy_enabled_by_name(self):
        cfg = Config(enabled_detectors=("high_entropy",))
        findings = scan("key " + self.HIGH_ENTROPY_VALUE, config=cfg)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "high_entropy")
        self.assertEqual(findings[0].type, "SECRET")

    def test_high_entropy_catalog_flags(self):
        # default_enabled=False, но enabled становится True при включении.
        default_info = [
            i for i in build_catalog(Config())
            if i.detector.name == "high_entropy"
        ][0]
        self.assertFalse(default_info.default_enabled)
        self.assertFalse(default_info.enabled)

        on_info = [
            i for i in build_catalog(Config(enabled_detectors=("high_entropy",)))
            if i.detector.name == "high_entropy"
        ][0]
        self.assertFalse(on_info.default_enabled)
        self.assertTrue(on_info.enabled)

    def test_names_aggressive_off_by_default(self):
        # Одиночное известное имя без контекста по умолчанию не маскируется.
        self.assertEqual(scan("Привет Роман как дела"), [])

    def test_names_aggressive_enabled_by_name(self):
        cfg = Config(enabled_detectors=("names_aggressive",))
        findings = scan("Привет Роман как дела", config=cfg)
        values = {f.value for f in findings}
        self.assertIn("Роман", values)
        self.assertTrue(all(f.detector == "names_aggressive" for f in findings))
        self.assertTrue(all(f.type == "PERSON" for f in findings))

    def test_names_aggressive_enabled_by_type_person(self):
        # Включение по типу PERSON тоже активирует опциональный детектор.
        cfg = Config(enabled_detectors=("PERSON",))
        active_names = {d.name for d in build_active(cfg)}
        self.assertIn("names_aggressive", active_names)

    def test_enabled_overrides_disabled_same_detector(self):
        # В registry enabled применяется после disabled, поэтому побеждает enabled.
        cfg = Config(disabled_detectors=("email",), enabled_detectors=("EMAIL",))
        self.assertIn("[EMAIL_1]", redact("a@b.com", config=cfg).masked_text)

    def test_enabling_unknown_name_is_noop(self):
        # Неизвестное имя в enabled — ничего не включает и не ломает.
        cfg = Config(enabled_detectors=("totally_unknown",))
        self.assertIn("[EMAIL_1]", redact("a@b.com", config=cfg).masked_text)


# =============================================================================
# allowlist
# =============================================================================
class AllowlistTests(unittest.TestCase):
    def test_allowlisted_domain_substring_skipped(self):
        # entry является подстрокой значения -> пропускается (см. engine._allowed).
        cfg = Config(allowlist=("example.com",))
        result = redact("письмо на john@example.com сегодня", config=cfg)
        self.assertIn("john@example.com", result.masked_text)

    def test_allowlisted_domain_skips_subdomain_value(self):
        # 'example.com' как подстрока ловит и поддомен.
        cfg = Config(allowlist=("example.com",))
        result = redact("письмо на a@sub.example.com тут", config=cfg)
        self.assertIn("a@sub.example.com", result.masked_text)

    def test_non_allowlisted_still_masked(self):
        cfg = Config(allowlist=("example.com",))
        result = redact("письмо на john@other.org сегодня", config=cfg)
        self.assertNotIn("john@other.org", result.masked_text)
        self.assertIn("[EMAIL_1]", result.masked_text)

    def test_allowlist_exact_value_skipped(self):
        # Точное совпадение значения с записью allowlist пропускается.
        cfg = Config(allowlist=("192.168.0.1",))
        result = redact("host 192.168.0.1 и 8.8.8.8", config=cfg)
        self.assertIn("192.168.0.1", result.masked_text)
        self.assertNotIn("[IP_2]", result.masked_text)
        # Не входящий в allowlist IP всё равно замаскирован.
        self.assertIn("[IP_1]", result.masked_text)

    def test_allowlist_case_insensitive(self):
        # allowlist приводится к нижнему регистру; значение тоже.
        cfg = Config(allowlist=("EXAMPLE.COM",))
        result = redact("на John@Example.Com теперь", config=cfg)
        self.assertIn("John@Example.Com", result.masked_text)

    def test_allowlist_multiple_entries(self):
        cfg = Config(allowlist=("example.com", "8.8.8.8"))
        result = redact("a@example.com и 8.8.8.8 и c@other.org", config=cfg)
        self.assertIn("a@example.com", result.masked_text)
        self.assertIn("8.8.8.8", result.masked_text)
        self.assertNotIn("c@other.org", result.masked_text)

    def test_empty_allowlist_masks_everything(self):
        cfg = Config(allowlist=())
        result = redact("на john@example.com теперь", config=cfg)
        self.assertNotIn("john@example.com", result.masked_text)


# =============================================================================
# placeholder_template
# =============================================================================
class PlaceholderTemplateTests(unittest.TestCase):
    def test_default_template(self):
        result = redact("a@b.com")
        self.assertEqual(result.masked_text, "[EMAIL_1]")

    def test_custom_template_format(self):
        cfg = Config(placeholder_template="<<{type}#{n}>>")
        result = redact("a@b.com и c@d.com", config=cfg)
        self.assertIn("<<EMAIL#1>>", result.masked_text)
        self.assertIn("<<EMAIL#2>>", result.masked_text)

    def test_custom_template_numbering_per_type(self):
        cfg = Config(placeholder_template="{type}-{n}")
        result = redact("a@b.com и 192.168.0.1", config=cfg)
        self.assertIn("EMAIL-1", result.masked_text)
        self.assertIn("IP-1", result.masked_text)

    def test_custom_template_stable_for_repeated_value(self):
        # Один и тот же email -> один и тот же плейсхолдер, нумерация не растёт.
        cfg = Config(placeholder_template="{{{type}:{n}}}")
        result = redact("a@b.com снова a@b.com", config=cfg)
        self.assertEqual(result.masked_text.count("{EMAIL:1}"), 2)
        self.assertNotIn("{EMAIL:2}", result.masked_text)

    def test_template_without_n_placeholder(self):
        # Шаблон без {n} допустим: format просто игнорирует лишний kwarg.
        cfg = Config(placeholder_template="[REDACTED:{type}]")
        result = redact("a@b.com и c@d.com", config=cfg)
        self.assertEqual(result.masked_text, "[REDACTED:EMAIL] и [REDACTED:EMAIL]")

    def test_template_flows_through_build_engine(self):
        cfg = Config(placeholder_template="##{type}{n}##")
        engine = build_engine(cfg)
        self.assertEqual(engine.placeholder_template, "##{type}{n}##")


# =============================================================================
# load_config (JSON-файл, дефолты, невалидный JSON)
# =============================================================================
class LoadConfigTests(unittest.TestCase):
    def test_load_full_config_from_file(self):
        payload = {
            "min_confidence": 0.5,
            "placeholder_template": "<{type}:{n}>",
            "disabled_detectors": ["email"],
            "enabled_detectors": ["high_entropy"],
            "allowlist": ["safe.com"],
            "custom_patterns": [
                {"name": "emp", "type": "EMPID", "pattern": r"EMP\d+",
                 "confidence": 0.9}
            ],
        }
        path = _write_temp_config(payload)
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)

        self.assertIsInstance(cfg, Config)
        self.assertAlmostEqual(cfg.min_confidence, 0.5)
        self.assertEqual(cfg.placeholder_template, "<{type}:{n}>")
        self.assertEqual(cfg.disabled_detectors, ("email",))
        self.assertEqual(cfg.enabled_detectors, ("high_entropy",))
        self.assertEqual(cfg.allowlist, ("safe.com",))
        self.assertEqual(len(cfg.custom_patterns), 1)
        self.assertEqual(cfg.custom_patterns[0]["type"], "EMPID")

    def test_loaded_config_is_usable_end_to_end(self):
        payload = {
            "placeholder_template": "<{type}:{n}>",
            "custom_patterns": [
                {"name": "emp", "type": "EMPID", "pattern": r"EMP\d+",
                 "confidence": 0.95}
            ],
        }
        path = _write_temp_config(payload)
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        result = redact("сотрудник EMP777 уволен", config=cfg)
        self.assertEqual(result.masked_text, "сотрудник <EMPID:1> уволен")

    def test_load_config_partial_uses_defaults(self):
        # Заданы не все поля — остальные берут значения по умолчанию.
        path = _write_temp_config({"min_confidence": 0.42})
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        self.assertAlmostEqual(cfg.min_confidence, 0.42)
        self.assertEqual(cfg.placeholder_template, "[{type}_{n}]")
        self.assertEqual(cfg.disabled_detectors, ())
        self.assertEqual(cfg.enabled_detectors, ())
        self.assertEqual(cfg.allowlist, ())
        self.assertEqual(cfg.custom_patterns, ())

    def test_load_empty_object_gives_all_defaults(self):
        path = _write_temp_config({})
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        self.assertEqual(cfg, Config())

    def test_load_config_none_without_default_file(self):
        # Без пути и без ./.datashield.json в cwd — чистые дефолты.
        # (полагаемся на то, что в корне проекта нет .datashield.json)
        default_path = os.path.join(os.getcwd(), ".datashield.json")
        if os.path.isfile(default_path):
            self.skipTest("в cwd присутствует .datashield.json")
        cfg = load_config(None)
        self.assertEqual(cfg, Config())

    def test_load_config_coerces_types(self):
        # min_confidence приходит строкой -> float(); template -> str().
        path = _write_temp_config({"min_confidence": "0.6", "placeholder_template": 5})
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        self.assertIsInstance(cfg.min_confidence, float)
        self.assertAlmostEqual(cfg.min_confidence, 0.6)
        self.assertEqual(cfg.placeholder_template, "5")

    def test_load_config_lists_become_tuples(self):
        path = _write_temp_config({
            "disabled_detectors": ["email", "ipv4"],
            "allowlist": ["a.com", "b.com"],
        })
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        self.assertIsInstance(cfg.disabled_detectors, tuple)
        self.assertEqual(cfg.disabled_detectors, ("email", "ipv4"))
        self.assertIsInstance(cfg.allowlist, tuple)

    def test_invalid_json_list_raises_value_error(self):
        # JSON-массив вместо объекта -> ValueError.
        path = _write_temp_config([1, 2, 3])
        try:
            with self.assertRaises(ValueError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_invalid_json_scalar_raises_value_error(self):
        # JSON-скаляр (число) — тоже не dict -> ValueError.
        path = _write_temp_config(42)
        try:
            with self.assertRaises(ValueError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_invalid_json_string_raises_value_error(self):
        path = _write_temp_config("just a string")
        try:
            with self.assertRaises(ValueError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_malformed_json_raises(self):
        # Битый JSON -> json.JSONDecodeError (подкласс ValueError).
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ not valid json ]")
        try:
            with self.assertRaises(ValueError):
                load_config(path)
        finally:
            os.unlink(path)


# =============================================================================
# Config как датакласс (frozen / дефолты)
# =============================================================================
class ConfigDataclassTests(unittest.TestCase):
    def test_defaults(self):
        cfg = Config()
        self.assertAlmostEqual(cfg.min_confidence, 0.7)
        self.assertEqual(cfg.placeholder_template, "[{type}_{n}]")
        self.assertEqual(cfg.disabled_detectors, ())
        self.assertEqual(cfg.enabled_detectors, ())
        self.assertEqual(cfg.allowlist, ())
        self.assertEqual(cfg.custom_patterns, ())

    def test_config_is_frozen(self):
        cfg = Config()
        with self.assertRaises(Exception):
            cfg.min_confidence = 0.9  # type: ignore[misc]

    def test_equality(self):
        self.assertEqual(Config(allowlist=("x",)), Config(allowlist=("x",)))
        self.assertNotEqual(Config(allowlist=("x",)), Config(allowlist=("y",)))


if __name__ == "__main__":
    unittest.main()
