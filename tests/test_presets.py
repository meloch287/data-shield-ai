"""Тесты пресетов соответствия (datashield.presets) и redact(preset=...).

Проверяем ФАКТИЧЕСКОЕ поведение, прочитанное из исходников:
  - datashield/presets.py: PRESETS, resolve_preset -> PresetResolution(only, min_confidence)
  - datashield/taxonomy.py: types_in_categories / category_of / severity_of
  - datashield/api.py: build_engine/redact с приоритетом explicit > preset > config
  - datashield/cli.py: --preset как argparse choices (неверный выбор -> код 2)

Пресеты сводятся к множеству разрешённых типов (only) через категории таксономии
и/или явный список плюс опциональный порог уверенности (min_confidence).
"""
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield import redact, scan
from datashield.api import build_engine
from datashield.config import Config
from datashield.presets import PRESETS, PresetResolution, resolve_preset
from datashield.taxonomy import (
    SEVERITY_ORDER,
    category_of,
    severity_of,
    types_in_categories,
)


def run_cli(argv, stdin_text=None):
    """Запускает CLI как в tests/test_cli.py; возвращает (code, out, err).

    argparse при неверном --preset вызывает sys.exit(2) -> SystemExit; ловим его
    и возвращаем .code, чтобы ассертить фактический код возврата.
    """
    import sys

    from datashield.cli import main

    out, err = io.StringIO(), io.StringIO()
    real_stdin = None
    if stdin_text is not None:
        real_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as exc:  # argparse invalid choice
                code = exc.code if isinstance(exc.code, int) else 1
    finally:
        if stdin_text is not None:
            sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


# Реальные значения, надёжно срабатывающие у соответствующих детекторов
# (проверено эмпирически на исходном коде проекта).
CARD = "4111 1111 1111 1111"          # -> CREDIT_CARD (financial, critical)
EMAIL = "alice@example.com"            # -> EMAIL (contact, medium)
OPENAI_KEY = "sk-proj-" + "a" * 48     # -> OPENAI_KEY (secret, critical)
ANTHROPIC_KEY = "sk-ant-api03-" + "A" * 84  # -> ANTHROPIC_KEY (secret, critical)


class ResolvePresetShapeTests(unittest.TestCase):
    """resolve_preset возвращает PresetResolution с ожидаемой формой."""

    def test_returns_preset_resolution(self):
        res = resolve_preset("pci-dss")
        self.assertIsInstance(res, PresetResolution)
        self.assertTrue(hasattr(res, "only"))
        self.assertTrue(hasattr(res, "min_confidence"))

    def test_all_known_presets_resolve(self):
        for name in PRESETS:
            res = resolve_preset(name)
            self.assertIsInstance(res, PresetResolution)

    def test_unknown_preset_raises_value_error(self):
        with self.assertRaises(ValueError):
            resolve_preset("does-not-exist")

    def test_unknown_preset_message_lists_available(self):
        with self.assertRaises(ValueError) as ctx:
            resolve_preset("nope")
        # Сообщение перечисляет доступные пресеты (отсортированные).
        msg = str(ctx.exception)
        for name in PRESETS:
            self.assertIn(name, msg)


class ResolvePresetOnlySetTests(unittest.TestCase):
    """only-множество каждого пресета совпадает с ожидаемым по таксономии."""

    def test_pci_dss_is_financial_plus_secret(self):
        res = resolve_preset("pci-dss")
        expected = types_in_categories(["financial", "secret"])
        self.assertEqual(res.only, expected)
        # Конкретно: карты и ключи внутри, но не имя/email/телефон.
        self.assertIn("CREDIT_CARD", res.only)
        self.assertIn("IBAN", res.only)
        self.assertIn("OPENAI_KEY", res.only)
        self.assertIn("ANTHROPIC_KEY", res.only)
        self.assertNotIn("EMAIL", res.only)
        self.assertNotIn("PERSON", res.only)
        self.assertNotIn("PHONE", res.only)

    def test_pci_dss_min_confidence_is_none(self):
        self.assertIsNone(resolve_preset("pci-dss").min_confidence)

    def test_secrets_only_is_exactly_secret_category(self):
        res = resolve_preset("secrets-only")
        expected = types_in_categories(["secret"])
        self.assertEqual(res.only, expected)
        # Все типы only принадлежат категории secret.
        for t in res.only:
            self.assertEqual(category_of(t), "secret")
        # И не содержит ничего из контактов/финансов/идентификаторов.
        self.assertNotIn("EMAIL", res.only)
        self.assertNotIn("CREDIT_CARD", res.only)
        self.assertNotIn("INN", res.only)

    def test_gdpr_is_broad_union_of_categories(self):
        res = resolve_preset("gdpr")
        expected = types_in_categories(
            ["contact", "person", "government_id", "financial", "health", "crypto"]
        )
        self.assertEqual(res.only, expected)
        # Широкий охват: контакты, личность, финансы, крипто — все внутри.
        self.assertIn("EMAIL", res.only)
        self.assertIn("PERSON", res.only)
        self.assertIn("CREDIT_CARD", res.only)
        self.assertIn("ETH_ADDRESS", res.only)
        self.assertIn("INN", res.only)
        # Но network (IP/MAC) НЕ входит в GDPR-набор.
        self.assertNotIn("IP", res.only)
        self.assertNotIn("MAC", res.only)

    def test_hipaa_categories(self):
        res = resolve_preset("hipaa")
        expected = types_in_categories(
            ["health", "person", "government_id", "contact"]
        )
        self.assertEqual(res.only, expected)
        self.assertIn("OMS_POLICY", res.only)   # health
        self.assertIn("EMAIL", res.only)        # contact
        self.assertIn("US_SSN", res.only)       # government_id
        # Финансовые карты не входят в hipaa.
        self.assertNotIn("CREDIT_CARD", res.only)

    def test_ru_gov_is_explicit_type_list(self):
        res = resolve_preset("ru-gov")
        expected = {
            "INN", "SNILS", "PASSPORT_RU", "OGRN", "OGRNIP", "KPP", "BIC",
            "BANK_ACCOUNT", "OMS_POLICY", "DRIVER_LICENSE_RU",
        }
        self.assertEqual(res.only, expected)
        self.assertIsNone(res.min_confidence)
        # ru-gov заведомо НЕ содержит секреты/email.
        self.assertNotIn("OPENAI_KEY", res.only)
        self.assertNotIn("EMAIL", res.only)

    def test_minimal_only_none_confidence_high(self):
        res = resolve_preset("minimal")
        self.assertIsNone(res.only)
        self.assertEqual(res.min_confidence, 0.9)


class TaxonomyMembershipTests(unittest.TestCase):
    """Связь пресет<->таксономия: каждый тип принадлежит ожидаемой категории."""

    def test_pci_types_belong_to_financial_or_secret(self):
        for t in resolve_preset("pci-dss").only:
            self.assertIn(category_of(t), ("financial", "secret"))

    def test_credit_card_severity_critical(self):
        # Точечное переопределение: CREDIT_CARD = critical, хотя financial=high.
        self.assertEqual(severity_of("CREDIT_CARD"), "critical")
        self.assertEqual(category_of("CREDIT_CARD"), "financial")

    def test_secret_types_are_critical(self):
        for t in resolve_preset("secrets-only").only:
            self.assertEqual(severity_of(t), "critical")

    def test_category_severity_mapping(self):
        # high-категории
        self.assertEqual(severity_of("INN"), "high")        # government_id
        self.assertEqual(severity_of("IBAN"), "high")       # financial
        self.assertEqual(severity_of("OMS_POLICY"), "high")  # health
        self.assertEqual(severity_of("ETH_ADDRESS"), "high")  # crypto
        # medium-категории
        self.assertEqual(severity_of("EMAIL"), "medium")    # contact
        self.assertEqual(severity_of("PERSON"), "medium")   # person
        # low-категория
        self.assertEqual(severity_of("IP"), "low")          # network

    def test_severity_order_low_to_critical(self):
        self.assertLess(SEVERITY_ORDER["low"], SEVERITY_ORDER["medium"])
        self.assertLess(SEVERITY_ORDER["medium"], SEVERITY_ORDER["high"])
        self.assertLess(SEVERITY_ORDER["high"], SEVERITY_ORDER["critical"])


class RedactEndToEndPresetTests(unittest.TestCase):
    """End-to-end: redact(preset=...) маскирует ровно ожидаемые типы."""

    TEXT = (
        f"Card {CARD} key {ANTHROPIC_KEY} api {OPENAI_KEY} "
        f"email {EMAIL} name John Smith"
    )

    def test_pci_masks_card_and_keys_not_contact(self):
        result = redact(self.TEXT, preset="pci-dss")
        # Карта и ключи замаскированы.
        self.assertIn("CREDIT_CARD", result.stats)
        self.assertIn("ANTHROPIC_KEY", result.stats)
        self.assertIn("OPENAI_KEY", result.stats)
        # Email НЕ замаскирован (вне pci-dss).
        self.assertNotIn("EMAIL", result.stats)
        self.assertIn(EMAIL, result.masked_text)
        # Оригинал карты исчез из вывода.
        self.assertNotIn(CARD, result.masked_text)

    def test_secrets_only_masks_only_secrets(self):
        result = redact(self.TEXT, preset="secrets-only")
        # Только секреты.
        self.assertIn("ANTHROPIC_KEY", result.stats)
        self.assertIn("OPENAI_KEY", result.stats)
        # Карта и email остаются нетронутыми.
        self.assertNotIn("CREDIT_CARD", result.stats)
        self.assertNotIn("EMAIL", result.stats)
        self.assertIn(CARD, result.masked_text)
        self.assertIn(EMAIL, result.masked_text)
        # Каждый найденный тип — секрет.
        for t in result.stats:
            self.assertEqual(category_of(t), "secret")

    def test_explicit_only_overrides_preset(self):
        # only=['EMAIL'] поверх pci-dss: маскируется ТОЛЬКО email.
        result = redact(self.TEXT, preset="pci-dss", only=["EMAIL"])
        self.assertEqual(set(result.stats), {"EMAIL"})
        self.assertNotIn(EMAIL, result.masked_text)
        # Карта и ключи остаются (preset перебит явным only).
        self.assertIn(CARD, result.masked_text)
        self.assertIn(ANTHROPIC_KEY, result.masked_text)

    def test_gdpr_masks_card_and_email(self):
        result = redact(self.TEXT, preset="gdpr")
        # gdpr охватывает и финансы, и контакты.
        self.assertIn("CREDIT_CARD", result.stats)
        self.assertIn("EMAIL", result.stats)
        self.assertNotIn(EMAIL, result.masked_text)
        self.assertNotIn(CARD, result.masked_text)

    def test_scan_with_preset_filters_types(self):
        # scan(preset=...) использует тот же фильтр only, что и redact.
        types = {f.type for f in scan(self.TEXT, preset="secrets-only")}
        self.assertTrue(types)
        for t in types:
            self.assertEqual(category_of(t), "secret")


class PresetEnginePrecedenceTests(unittest.TestCase):
    """build_engine: приоритет explicit > preset > config для only/min_confidence."""

    def test_minimal_preset_raises_min_confidence(self):
        engine = build_engine(Config(), preset="minimal")
        # minimal задаёт min_confidence=0.9 и не ограничивает типы.
        self.assertEqual(engine.min_confidence, 0.9)
        self.assertIsNone(engine.only)

    def test_explicit_min_confidence_overrides_minimal_preset(self):
        engine = build_engine(Config(), preset="minimal", min_confidence=0.5)
        self.assertEqual(engine.min_confidence, 0.5)

    def test_preset_sets_only_on_engine(self):
        engine = build_engine(Config(), preset="secrets-only")
        # engine.only хранит типы в верхнем регистре (множество).
        self.assertEqual(engine.only, types_in_categories(["secret"]))

    def test_preset_from_config_applied(self):
        # Пресет может приходить из конфига, не только из аргумента.
        engine = build_engine(Config(preset="pci-dss"))
        self.assertEqual(
            engine.only, types_in_categories(["financial", "secret"])
        )

    def test_explicit_only_overrides_config_preset(self):
        engine = build_engine(Config(preset="pci-dss"), only=["EMAIL"])
        self.assertEqual(engine.only, {"EMAIL"})

    def test_unknown_preset_in_build_engine_raises(self):
        with self.assertRaises(ValueError):
            build_engine(Config(), preset="bogus")


class PresetCliTests(unittest.TestCase):
    """CLI: --preset как набор choices; неверный выбор -> код возврата 2."""

    def test_redact_unknown_preset_exit_2(self):
        # argparse отклоняет неизвестный --preset (invalid choice) -> exit 2.
        code, _, err = run_cli(["redact", "--preset", "bogus"], stdin_text="x")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)

    def test_scan_unknown_preset_exit_2(self):
        code, _, err = run_cli(["scan", "--preset", "bogus"], stdin_text="x")
        self.assertEqual(code, 2)

    def test_redact_pci_preset_masks_card_not_email(self):
        text = f"card {CARD} mail {EMAIL}"
        code, out, _ = run_cli(["redact", "--preset", "pci-dss"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertNotIn(CARD, out)
        self.assertIn(EMAIL, out)  # email вне pci-dss — остаётся

    def test_scan_json_includes_category_and_severity(self):
        import json

        text = f"card {CARD}"
        code, out, _ = run_cli(
            ["scan", "--preset", "pci-dss", "--json"], stdin_text=text
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload)
        entry = payload[0]
        self.assertEqual(entry["type"], "CREDIT_CARD")
        self.assertEqual(entry["category"], "financial")
        self.assertEqual(entry["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
