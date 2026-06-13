"""Тесты блока H: регуляторное соответствие в отчёте RedactionResult.report().

Проверяется реальное поведение:
- compliance.py: REGULATIONS, regulations_for(), classify();
- RedactionResult.report() содержит ключ "compliance" == classify(найденных типов);
- секреты (категория 'secret') не относятся ни к одному регламенту;
- PCI-DSS покрывает только категорию 'financial';
- отчёт не содержит сырых значений;
- CLI `redact --report` пишет JSON с блоком compliance и без сырых значений;
- discovery плагинов через monkeypatch importlib.metadata.entry_points
  (без установки пакетов): хороший плагин попадает в каталог, битый — пропускается.

Источники прочитаны перед написанием: datashield/compliance.py, datashield/taxonomy.py,
datashield/engine.py, datashield/cli.py, datashield/detectors/registry.py.
"""
import importlib.metadata as importlib_metadata
import io
import json
import os
import sys
import tempfile
import unittest

from datashield import redact
from datashield.cli import main
from datashield.compliance import REGULATIONS, classify, regulations_for
from datashield.config import Config
from datashield.detectors import registry
from datashield.detectors.base import RegexDetector
from datashield.taxonomy import category_of

# Документ с email + картой + полисом ОМС.
# Карта 4111 1111 1111 1111 — валидный тестовый номер (проходит Луна).
# "полис ОМС <16 цифр>" — ключевое слово поднимает уверенность OMS_POLICY до 0.92.
DOC = "email: john@example.com, card 4111 1111 1111 1111, полис ОМС 1234567890123456"

# Сырые значения, которые НИКОГДА не должны утечь в отчёт.
RAW_VALUES = (
    "john@example.com",
    "4111 1111 1111 1111",
    "4111111111111111",
    "1234567890123456",
)

CLEAN_TEXT = "the quarterly numbers improved and the build is green"

# Базовые размеры каталога, вычисленные в момент запуска тестов, чтобы ассерты
# не ломались при добавлении новых детекторов (на момент написания — 90/86/83).
_BASELINE_CATALOG = registry.build_catalog(Config())
DETECTOR_COUNT = len(_BASELINE_CATALOG)
DEFAULT_ON_COUNT = sum(1 for i in _BASELINE_CATALOG if i.default_enabled)
TYPE_COUNT = len({i.detector.type for i in _BASELINE_CATALOG})


# --------------------------------------------------------------------------- #
# Уровень compliance.py — базовые факты маппинга.
# --------------------------------------------------------------------------- #
class ComplianceModuleTests(unittest.TestCase):
    def test_regulations_keys(self):
        self.assertEqual(
            sorted(REGULATIONS.keys()), ["CCPA", "GDPR", "HIPAA", "PCI-DSS"]
        )

    def test_pci_dss_only_covers_financial(self):
        # PCI-DSS покрывает ровно категорию 'financial'.
        self.assertEqual(REGULATIONS["PCI-DSS"], {"financial"})

    def test_regulations_for_email(self):
        # contact: GDPR/HIPAA/CCPA, но НЕ PCI-DSS.
        self.assertEqual(regulations_for("EMAIL"), ["CCPA", "GDPR", "HIPAA"])

    def test_regulations_for_credit_card(self):
        # financial попадает во все четыре регламента.
        self.assertEqual(
            regulations_for("CREDIT_CARD"), ["CCPA", "GDPR", "HIPAA", "PCI-DSS"]
        )

    def test_regulations_for_oms_policy_health(self):
        # health (OMS_POLICY): GDPR/HIPAA, но НЕ CCPA и НЕ PCI-DSS.
        self.assertEqual(category_of("OMS_POLICY"), "health")
        self.assertEqual(regulations_for("OMS_POLICY"), ["GDPR", "HIPAA"])

    def test_secret_category_maps_to_no_regulation(self):
        # Секреты не относятся ни к одному регламенту.
        self.assertEqual(regulations_for("SECRET"), [])
        self.assertEqual(regulations_for("AWS_SECRET_KEY"), [])
        self.assertEqual(category_of("SECRET"), "secret")

    def test_regulations_for_unknown_type(self):
        # Неизвестный тип (категория 'other') → пусто.
        self.assertEqual(regulations_for("NONEXISTENT_TYPE_XYZ"), [])

    def test_regulations_for_returns_sorted(self):
        regs = regulations_for("CREDIT_CARD")
        self.assertEqual(regs, sorted(regs))

    def test_classify_empty_iterable(self):
        self.assertEqual(classify([]), {})

    def test_classify_single_type(self):
        self.assertEqual(
            classify({"EMAIL"}),
            {"CCPA": ["EMAIL"], "GDPR": ["EMAIL"], "HIPAA": ["EMAIL"]},
        )

    def test_classify_email_card_oms(self):
        # Полный сценарий: email+card+OMS_POLICY.
        expected = {
            "CCPA": ["CREDIT_CARD", "EMAIL"],
            "GDPR": ["CREDIT_CARD", "EMAIL", "OMS_POLICY"],
            "HIPAA": ["CREDIT_CARD", "EMAIL", "OMS_POLICY"],
            "PCI-DSS": ["CREDIT_CARD"],
        }
        self.assertEqual(classify({"EMAIL", "CREDIT_CARD", "OMS_POLICY"}), expected)

    def test_classify_values_are_sorted(self):
        result = classify({"CREDIT_CARD", "EMAIL", "OMS_POLICY"})
        for reg, types in result.items():
            self.assertEqual(types, sorted(types), f"{reg} не отсортирован")

    def test_classify_keys_are_sorted(self):
        result = classify({"CREDIT_CARD", "EMAIL", "OMS_POLICY"})
        self.assertEqual(list(result.keys()), sorted(result.keys()))

    def test_classify_secret_only_yields_empty(self):
        # Набор только из секретов → никаких регламентов.
        self.assertEqual(classify({"SECRET", "AWS_SECRET_KEY"}), {})

    def test_classify_dedups_types(self):
        # Повтор типа во входе не дублируется в результате.
        result = classify(["EMAIL", "EMAIL"])
        self.assertEqual(result["GDPR"], ["EMAIL"])

    def test_classify_no_empty_regulation_lists(self):
        # Если регламент в результате — список его типов непуст.
        result = classify({"EMAIL", "CREDIT_CARD", "OMS_POLICY"})
        for types in result.values():
            self.assertTrue(types)


# --------------------------------------------------------------------------- #
# RedactionResult.report() — ключ "compliance".
# --------------------------------------------------------------------------- #
class ReportComplianceTests(unittest.TestCase):
    def setUp(self):
        self.result = redact(DOC)
        # Детерминированная соль, чтобы тесты не зависели от os.urandom.
        self.report = self.result.report(salt=b"\x00" * 16)

    def test_report_has_compliance_key(self):
        self.assertIn("compliance", self.report)

    def test_report_compliance_is_dict(self):
        self.assertIsInstance(self.report["compliance"], dict)

    def test_compliance_equals_classify_of_found_types(self):
        # Ключ "compliance" == classify множества найденных типов.
        found_types = {f.type for f in self.result.findings}
        self.assertEqual(self.report["compliance"], classify(found_types))

    def test_compliance_matches_expected_regulations(self):
        expected = {
            "CCPA": ["CREDIT_CARD", "EMAIL"],
            "GDPR": ["CREDIT_CARD", "EMAIL", "OMS_POLICY"],
            "HIPAA": ["CREDIT_CARD", "EMAIL", "OMS_POLICY"],
            "PCI-DSS": ["CREDIT_CARD"],
        }
        self.assertEqual(self.report["compliance"], expected)

    def test_document_yields_all_four_regulations(self):
        self.assertEqual(
            sorted(self.report["compliance"].keys()),
            ["CCPA", "GDPR", "HIPAA", "PCI-DSS"],
        )

    def test_pci_dss_only_credit_card(self):
        # В этом документе PCI-DSS затрагивает только карту.
        self.assertEqual(self.report["compliance"]["PCI-DSS"], ["CREDIT_CARD"])

    def test_ccpa_excludes_health_type(self):
        # CCPA не покрывает health → OMS_POLICY не в списке CCPA.
        self.assertNotIn("OMS_POLICY", self.report["compliance"]["CCPA"])

    def test_compliance_consistent_with_stats_keys(self):
        # Каждый тип в compliance действительно есть в stats (найден в документе).
        stats_types = set(self.report["stats"].keys())
        for types in self.report["compliance"].values():
            for t in types:
                self.assertIn(t, stats_types)

    def test_compliance_types_subset_of_found(self):
        found = {f.type for f in self.result.findings}
        for types in self.report["compliance"].values():
            self.assertTrue(set(types) <= found)

    def test_stats_keys_match_finding_types(self):
        # Согласованность stats и findings (опора для сравнения выше).
        self.assertEqual(
            set(self.report["stats"].keys()),
            {f.type for f in self.result.findings},
        )

    def test_report_top_level_keys(self):
        self.assertEqual(
            sorted(self.report.keys()),
            ["compliance", "entries", "salt", "stats", "total"],
        )

    def test_compliance_never_contains_raw_values(self):
        # В блоке compliance не должно быть ни одного сырого значения.
        blob = json.dumps(self.report["compliance"], ensure_ascii=False)
        for raw in RAW_VALUES:
            self.assertNotIn(raw, blob)

    def test_full_report_never_contains_raw_values(self):
        # И во всём отчёте целиком (entries содержат хеши/preview, не оригиналы).
        blob = json.dumps(self.report, ensure_ascii=False)
        for raw in RAW_VALUES:
            self.assertNotIn(raw, blob)

    def test_compliance_independent_of_salt(self):
        # compliance не зависит от соли (соль влияет только на хеши).
        rep_a = self.result.report(salt=b"\x01" * 16)
        rep_b = self.result.report(salt=b"\x02" * 16)
        self.assertEqual(rep_a["compliance"], rep_b["compliance"])

    def test_total_matches_findings(self):
        self.assertEqual(self.report["total"], len(self.result.findings))


class ReportCleanTextTests(unittest.TestCase):
    def test_clean_text_compliance_empty(self):
        # Чистый текст → compliance == {}.
        report = redact(CLEAN_TEXT).report(salt=b"\x00" * 16)
        self.assertEqual(report["compliance"], {})

    def test_clean_text_no_findings(self):
        result = redact(CLEAN_TEXT)
        self.assertEqual(result.findings, [])

    def test_clean_text_stats_empty(self):
        report = redact(CLEAN_TEXT).report(salt=b"\x00" * 16)
        self.assertEqual(report["stats"], {})

    def test_clean_text_compliance_consistent_with_stats(self):
        report = redact(CLEAN_TEXT).report(salt=b"\x00" * 16)
        self.assertEqual(report["compliance"], classify(report["stats"].keys()))


class ReportSecretOnlyTests(unittest.TestCase):
    """Документ только с секретом → compliance пуст (секреты вне регламентов)."""

    SECRET_DOC = "export AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY now"

    def test_secret_detected(self):
        result = redact(self.SECRET_DOC)
        types = {f.type for f in result.findings}
        # Что-то из категории secret должно найтись.
        self.assertTrue(types, "ожидалась хотя бы одна находка")
        for t in types:
            self.assertEqual(category_of(t), "secret")

    def test_secret_compliance_empty(self):
        report = redact(self.SECRET_DOC).report(salt=b"\x00" * 16)
        self.assertEqual(report["compliance"], {})


# --------------------------------------------------------------------------- #
# CLI: redact --report пишет JSON с блоком compliance и без сырых значений.
# --------------------------------------------------------------------------- #
class CliRedactReportTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.in_path = os.path.join(self.tmpdir, "in.txt")
        self.out_path = os.path.join(self.tmpdir, "out.txt")
        self.report_path = os.path.join(self.tmpdir, "report.json")
        with open(self.in_path, "w", encoding="utf-8") as handle:
            handle.write(DOC)

    def tearDown(self):
        for path in (self.in_path, self.out_path, self.report_path):
            if os.path.exists(path):
                os.unlink(path)
        os.rmdir(self.tmpdir)

    def _run(self):
        return main(
            [
                "redact",
                "-i", self.in_path,
                "-o", self.out_path,
                "--report", self.report_path,
            ]
        )

    def test_exit_code_zero(self):
        self.assertEqual(self._run(), 0)

    def test_report_file_written(self):
        self._run()
        self.assertTrue(os.path.exists(self.report_path))

    def test_report_file_has_compliance_block(self):
        self._run()
        with open(self.report_path, encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertIn("compliance", report)
        self.assertEqual(
            sorted(report["compliance"].keys()),
            ["CCPA", "GDPR", "HIPAA", "PCI-DSS"],
        )

    def test_report_file_compliance_matches_classify(self):
        self._run()
        with open(self.report_path, encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertEqual(
            report["compliance"], classify(report["stats"].keys())
        )

    def test_report_file_no_raw_values(self):
        self._run()
        with open(self.report_path, encoding="utf-8") as handle:
            blob = handle.read()
        for raw in RAW_VALUES:
            self.assertNotIn(raw, blob)

    def test_masked_output_no_raw_values(self):
        self._run()
        with open(self.out_path, encoding="utf-8") as handle:
            masked = handle.read()
        for raw in RAW_VALUES:
            self.assertNotIn(raw, masked)


# --------------------------------------------------------------------------- #
# CLI: команда `types` печатает каждый тип с категорией/критичностью/регламентами.
# --------------------------------------------------------------------------- #
class CliTypesCommandTests(unittest.TestCase):
    def _capture_types(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = main(["types"])
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_types_exit_zero(self):
        rc, _ = self._capture_types()
        self.assertEqual(rc, 0)

    def test_types_lists_68_types(self):
        # По одной строке на тип каталога (число вычислено из живого каталога;
        # на момент написания — 83 типа).
        _, out = self._capture_types()
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), TYPE_COUNT)

    def test_types_email_line_shows_regulations(self):
        _, out = self._capture_types()
        email_lines = [ln for ln in out.splitlines() if ln.split()[:1] == ["EMAIL"]]
        self.assertEqual(len(email_lines), 1)
        line = email_lines[0]
        self.assertIn("contact", line)
        self.assertIn("CCPA", line)
        self.assertIn("GDPR", line)
        self.assertIn("HIPAA", line)

    def test_types_oms_line_health_gdpr_hipaa(self):
        _, out = self._capture_types()
        oms_lines = [ln for ln in out.splitlines() if "OMS_POLICY" in ln]
        self.assertEqual(len(oms_lines), 1)
        line = oms_lines[0]
        self.assertIn("health", line)
        self.assertIn("GDPR", line)
        self.assertIn("HIPAA", line)
        # CCPA/PCI-DSS не покрывают health.
        self.assertNotIn("CCPA", line)
        self.assertNotIn("PCI-DSS", line)

    def test_types_secret_line_has_dash(self):
        # Тип-секрет печатает прочерк вместо регламентов.
        _, out = self._capture_types()
        secret_lines = [
            ln for ln in out.splitlines() if ln.split()[:1] == ["SECRET"]
        ]
        self.assertEqual(len(secret_lines), 1)
        self.assertIn("—", secret_lines[0])  # символ — (em dash)


# --------------------------------------------------------------------------- #
# Plugin discovery — monkeypatch importlib.metadata.entry_points (без pip).
# --------------------------------------------------------------------------- #
class _FakeEntryPoint:
    """Минимальный stub entry point: .load() возвращает builder-функцию."""

    def __init__(self, builder):
        self._builder = builder

    def load(self):
        return self._builder


class _FakeEntryPoints:
    """Stub результата entry_points() с современным .select(group=...)."""

    def __init__(self, eps):
        self._eps = eps

    def select(self, group=None):
        if group == "datashield.detectors":
            return list(self._eps)
        return []


def _good_plugin_builder():
    return [RegexDetector("myplugin", "MYPLUGINTYPE", r"XYZ\d+", 0.99)]


def _broken_plugin_builder():
    raise RuntimeError("плагин сломан")


class PluginDiscoveryTests(unittest.TestCase):
    """Открытие сторонних детекторов через entry_points группы
    'datashield.detectors'. Подменяем importlib.metadata.entry_points фейком —
    БЕЗ установки пакетов."""

    def setUp(self):
        self._orig_entry_points = importlib_metadata.entry_points
        self.addCleanup(
            setattr, importlib_metadata, "entry_points", self._orig_entry_points
        )

    def _patch(self, eps):
        importlib_metadata.entry_points = lambda: _FakeEntryPoints(eps)

    def test_good_plugin_detector_in_catalog(self):
        self._patch([_FakeEntryPoint(_good_plugin_builder)])
        catalog = registry.build_catalog(Config())
        types = {info.detector.type for info in catalog}
        self.assertIn("MYPLUGINTYPE", types)

    def test_plugin_detector_enabled_by_default(self):
        self._patch([_FakeEntryPoint(_good_plugin_builder)])
        catalog = registry.build_catalog(Config())
        plugin = next(
            info for info in catalog if info.detector.type == "MYPLUGINTYPE"
        )
        self.assertTrue(plugin.enabled)
        self.assertTrue(plugin.default_enabled)

    def test_broken_plugin_is_skipped(self):
        # Битый entry point не добавляет детекторов и не валит build_catalog.
        self._patch([_FakeEntryPoint(_broken_plugin_builder)])
        catalog = registry.build_catalog(Config())
        # Каталог по-прежнему собирается (ядро на месте).
        types = {info.detector.type for info in catalog}
        self.assertIn("EMAIL", types)
        self.assertNotIn("MYPLUGINTYPE", types)

    def test_broken_plugin_does_not_crash(self):
        self._patch([_FakeEntryPoint(_broken_plugin_builder)])
        try:
            registry.build_catalog(Config())
        except Exception as exc:  # pragma: no cover
            self.fail(f"build_catalog упал из-за битого плагина: {exc!r}")

    def test_good_and_broken_mixed(self):
        # Хороший плагин подключается, битый — молча пропускается.
        self._patch(
            [
                _FakeEntryPoint(_good_plugin_builder),
                _FakeEntryPoint(_broken_plugin_builder),
            ]
        )
        catalog = registry.build_catalog(Config())
        types = {info.detector.type for info in catalog}
        self.assertIn("MYPLUGINTYPE", types)
        self.assertIn("EMAIL", types)

    def test_no_plugins_default_catalog_counts(self):
        # Без плагинов каталог сохраняет базовую форму (числа вычислены из
        # живого каталога; на момент написания — 90/86/83).
        self._patch([])
        catalog = registry.build_catalog(Config())
        self.assertEqual(len(catalog), DETECTOR_COUNT)
        self.assertEqual(sum(1 for i in catalog if i.default_enabled), DEFAULT_ON_COUNT)
        self.assertEqual(len({i.detector.type for i in catalog}), TYPE_COUNT)

    def test_plugin_added_to_active_set(self):
        self._patch([_FakeEntryPoint(_good_plugin_builder)])
        active = registry.build_active(Config())
        self.assertIn("MYPLUGINTYPE", {d.type for d in active})


if __name__ == "__main__":
    unittest.main()
