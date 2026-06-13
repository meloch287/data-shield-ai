"""Тесты фильтра по критичности (min_severity).

Проверяют BLOCK D: min_severity через redact/scan/build_engine и Config.

  - min_severity="critical" оставляет только critical-типы (карта, секреты) и
    отбрасывает email (medium) и IP (low);
  - "high" оставляет high+critical, отбрасывает medium/low;
  - невалидное/пустое значение severity = без фильтрации;
  - report() содержит поля category+severity;
  - scan --json (через cli.main) содержит category+severity;
  - фильтр композируется с only и preset.

Поведение зафиксировано по реальному коду:
  datashield/engine.py (RedactionEngine.analyze, RedactionResult.report),
  datashield/api.py (build_engine/redact/scan), datashield/taxonomy.py,
  datashield/config.py (Config.min_severity), datashield/cli.py (_cmd_scan).
"""
from __future__ import annotations

import io
import json
import sys
import unittest

from datashield import build_engine, redact, scan
from datashield.config import Config
from datashield.taxonomy import SEVERITY_ORDER, category_of, severity_of

# Текст с по одному типу на каждый уровень критичности.
#   EMAIL        -> contact  -> medium
#   CREDIT_CARD  -> financial -> critical (точечное переопределение)
#   IP           -> network  -> low
#   ANTHROPIC_KEY -> secret   -> critical
TEXT = (
    "email a@b.com card 4111 1111 1111 1111 ip 192.168.0.1 key "
    "sk-ant-api03-" + "A" * 80
)
# Текст с high-типом: ETH_ADDRESS -> crypto -> high.
TEXT_HIGH = (
    "email a@b.com card 4111 1111 1111 1111 ip 10.0.0.1 "
    "wallet 0x52908400098527886E0F7030069857D2E4169EE7"
)


def _types(findings) -> set:
    return {f.type for f in findings}


def _run_cli(argv, stdin_text):
    """Запускает cli.main с подменой stdin/stdout, возвращает (rc, stdout)."""
    from datashield import cli

    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(stdin_text)
    out = io.StringIO()
    sys.stdout = out
    try:
        rc = cli.main(argv)
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    return rc, out.getvalue()


class TaxonomySanityTest(unittest.TestCase):
    """Закрепляет предпосылки, на которых строятся остальные тесты."""

    def test_severity_assignments(self):
        self.assertEqual(severity_of("CREDIT_CARD"), "critical")
        self.assertEqual(severity_of("ANTHROPIC_KEY"), "critical")
        self.assertEqual(severity_of("EMAIL"), "medium")
        self.assertEqual(severity_of("IP"), "low")
        self.assertEqual(severity_of("ETH_ADDRESS"), "high")

    def test_severity_order(self):
        self.assertEqual(SEVERITY_ORDER, {"low": 0, "medium": 1, "high": 2, "critical": 3})

    def test_sample_text_yields_all_levels(self):
        # Базовый текст без фильтра действительно содержит все четыре типа.
        self.assertEqual(
            _types(scan(TEXT)),
            {"EMAIL", "CREDIT_CARD", "IP", "ANTHROPIC_KEY"},
        )


class ScanMinSeverityTest(unittest.TestCase):
    def test_critical_keeps_only_critical(self):
        # critical оставляет карту и секрет, отбрасывает email(medium) и IP(low).
        self.assertEqual(
            _types(scan(TEXT, min_severity="critical")),
            {"CREDIT_CARD", "ANTHROPIC_KEY"},
        )

    def test_critical_drops_medium_and_low(self):
        kept = _types(scan(TEXT, min_severity="critical"))
        self.assertNotIn("EMAIL", kept)
        self.assertNotIn("IP", kept)

    def test_high_keeps_high_and_critical(self):
        # high оставляет ETH(high)+CREDIT_CARD(critical), отбрасывает email/IP.
        kept = _types(scan(TEXT_HIGH, min_severity="high"))
        self.assertIn("ETH_ADDRESS", kept)
        self.assertIn("CREDIT_CARD", kept)
        self.assertNotIn("EMAIL", kept)
        self.assertNotIn("IP", kept)

    def test_medium_keeps_medium_high_critical_drops_low(self):
        kept = _types(scan(TEXT, min_severity="medium"))
        self.assertEqual(kept, {"EMAIL", "CREDIT_CARD", "ANTHROPIC_KEY"})
        self.assertNotIn("IP", kept)

    def test_low_keeps_everything(self):
        self.assertEqual(
            _types(scan(TEXT, min_severity="low")),
            {"EMAIL", "CREDIT_CARD", "IP", "ANTHROPIC_KEY"},
        )

    def test_empty_severity_no_filtering(self):
        self.assertEqual(_types(scan(TEXT, min_severity="")), _types(scan(TEXT)))

    def test_invalid_severity_no_filtering(self):
        # Неизвестный уровень трактуется как rank -1 -> фильтр выключен.
        self.assertEqual(
            _types(scan(TEXT, min_severity="bogus")),
            {"EMAIL", "CREDIT_CARD", "IP", "ANTHROPIC_KEY"},
        )

    def test_severity_case_insensitive(self):
        # min_severity приводится к нижнему регистру в движке.
        self.assertEqual(
            _types(scan(TEXT, min_severity="CRITICAL")),
            {"CREDIT_CARD", "ANTHROPIC_KEY"},
        )


class RedactMinSeverityTest(unittest.TestCase):
    def test_critical_masks_only_critical(self):
        result = redact(TEXT, min_severity="critical")
        self.assertEqual(_types(result.findings), {"CREDIT_CARD", "ANTHROPIC_KEY"})
        # Email и IP остаются в выводе нетронутыми.
        self.assertIn("a@b.com", result.masked_text)
        self.assertIn("192.168.0.1", result.masked_text)
        # Карта замаскирована.
        self.assertNotIn("4111 1111 1111 1111", result.masked_text)

    def test_stats_reflect_filter(self):
        result = redact(TEXT, min_severity="critical")
        self.assertNotIn("EMAIL", result.stats)
        self.assertNotIn("IP", result.stats)
        self.assertIn("CREDIT_CARD", result.stats)


class BuildEngineMinSeverityTest(unittest.TestCase):
    def test_rank_for_known_level(self):
        engine = build_engine(min_severity="critical")
        self.assertEqual(engine.min_severity_rank, SEVERITY_ORDER["critical"])

    def test_rank_disabled_by_default(self):
        self.assertEqual(build_engine().min_severity_rank, -1)

    def test_rank_disabled_for_empty(self):
        self.assertEqual(build_engine(min_severity="").min_severity_rank, -1)

    def test_rank_disabled_for_invalid(self):
        self.assertEqual(build_engine(min_severity="nope").min_severity_rank, -1)

    def test_engine_analyze_applies_filter(self):
        engine = build_engine(min_severity="critical")
        self.assertEqual(
            _types(engine.analyze(TEXT)),
            {"CREDIT_CARD", "ANTHROPIC_KEY"},
        )


class ConfigMinSeverityTest(unittest.TestCase):
    def test_config_default_is_empty(self):
        self.assertEqual(Config().min_severity, "")

    def test_config_min_severity_filters(self):
        cfg = Config(min_severity="critical")
        self.assertEqual(
            _types(scan(TEXT, config=cfg)),
            {"CREDIT_CARD", "ANTHROPIC_KEY"},
        )

    def test_explicit_arg_overrides_config(self):
        # config.min_severity="critical", но явный аргумент min_severity="low".
        cfg = Config(min_severity="critical")
        self.assertEqual(
            _types(scan(TEXT, config=cfg, min_severity="low")),
            {"EMAIL", "CREDIT_CARD", "IP", "ANTHROPIC_KEY"},
        )

    def test_config_empty_means_no_filter(self):
        cfg = Config(min_severity="")
        self.assertEqual(build_engine(config=cfg).min_severity_rank, -1)


class ReportFieldsTest(unittest.TestCase):
    def test_entries_include_category_and_severity(self):
        report = redact("email a@b.com card 4111 1111 1111 1111").report()
        self.assertGreater(len(report["entries"]), 0)
        for entry in report["entries"]:
            self.assertIn("category", entry)
            self.assertIn("severity", entry)
            self.assertEqual(entry["category"], category_of(entry["type"]))
            self.assertEqual(entry["severity"], severity_of(entry["type"]))

    def test_report_entry_values(self):
        report = redact("card 4111 1111 1111 1111").report()
        entry = next(e for e in report["entries"] if e["type"] == "CREDIT_CARD")
        self.assertEqual(entry["category"], "financial")
        self.assertEqual(entry["severity"], "critical")


class ScanJsonCliTest(unittest.TestCase):
    def test_scan_json_includes_category_and_severity(self):
        rc, out = _run_cli(["scan", "--json"], TEXT)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertGreater(len(data), 0)
        for item in data:
            self.assertIn("category", item)
            self.assertIn("severity", item)
            self.assertEqual(item["category"], category_of(item["type"]))
            self.assertEqual(item["severity"], severity_of(item["type"]))

    def test_scan_json_min_severity_filters(self):
        rc, out = _run_cli(["scan", "--json", "--min-severity", "critical"], TEXT)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(
            {item["type"] for item in data},
            {"CREDIT_CARD", "ANTHROPIC_KEY"},
        )


class ComposeWithOnlyAndPresetTest(unittest.TestCase):
    def test_compose_with_only(self):
        # only сужает до EMAIL+CREDIT_CARD; min_severity=critical отбрасывает EMAIL.
        kept = _types(
            scan(TEXT, only=["EMAIL", "CREDIT_CARD"], min_severity="critical")
        )
        self.assertEqual(kept, {"CREDIT_CARD"})

    def test_compose_with_preset(self):
        # gdpr охватывает contact/financial/... ; min_severity=critical оставляет
        # из этого набора только critical (CREDIT_CARD), но не secret-ключ
        # (его нет в gdpr).
        kept = _types(scan(TEXT, preset="gdpr", min_severity="critical"))
        self.assertEqual(kept, {"CREDIT_CARD"})

    def test_preset_alone_keeps_medium(self):
        # Без min_severity пресет gdpr оставляет email(medium) и IP не входит
        # в gdpr-набор. Подтверждает, что отсев в композиции делает именно severity.
        kept = _types(scan(TEXT, preset="gdpr"))
        self.assertIn("EMAIL", kept)
        self.assertIn("CREDIT_CARD", kept)
        self.assertNotIn("IP", kept)


if __name__ == "__main__":
    unittest.main()
