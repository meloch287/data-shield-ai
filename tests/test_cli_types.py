"""Тесты команды CLI `datashield types`.

Проверяют фактическое поведение `datashield.cli.main(["types"])`:
по строке на каждый тип каталога (68 типов) с типом, категорией, критичностью
и регламентами (через запятую) либо «—» для секретов. Строки отсортированы
по типу. Также проверяется маппинг compliance.regulations_for/classify и то,
что обнаружение плагинов через importlib.metadata.entry_points
монкипатчится (без установки пакетов): хороший плагин добавляется в каталог,
а сломанный entry point пропускается и не валит build_catalog.

Всё на stdlib unittest; stdout перехватывается через redirect_stdout.
"""
from __future__ import annotations

import importlib.metadata as _md
import io
import unittest
from contextlib import redirect_stdout

from datashield.cli import main
from datashield.compliance import REGULATIONS, classify, regulations_for
from datashield.config import Config
from datashield.detectors import registry
from datashield.detectors.base import RegexDetector
from datashield.taxonomy import category_of, severity_of


def _run_types(argv=("types",)):
    """Запустить CLI и вернуть (код возврата, stdout)."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


def _parsed_lines(text):
    """Разобрать каждую непустую строку вывода `types` в первые три поля.

    Формат строки: '  TYPE  CATEGORY  SEVERITY  REGS...'. Регламенты могут
    содержать пробелы (', ' разделитель), поэтому берём первые три токена,
    а остаток считаем полем регламентов.
    """
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        type_name, category, severity = parts[0], parts[1], parts[2]
        regs = " ".join(parts[3:])
        rows.append((type_name, category, severity, regs))
    return rows


# Точная строка регламентов, как печатает CLI (', '.join(regulations_for(t))).
def _regs_field(type_name):
    return ", ".join(regulations_for(type_name)) or "—"


CATALOG_TYPES = sorted({i.detector.type for i in registry.build_catalog(Config())})


class TypesCommandBasicTests(unittest.TestCase):
    """Базовый запуск команды и форма вывода."""

    def test_returns_zero(self):
        code, _ = _run_types()
        self.assertEqual(code, 0)

    def test_produces_output(self):
        _, out = _run_types()
        self.assertTrue(out.strip())

    def test_one_line_per_catalog_type(self):
        # 68 типов в каталоге по умолчанию → ровно 68 непустых строк.
        _, out = _run_types()
        rows = _parsed_lines(out)
        self.assertEqual(len(rows), 68)

    def test_line_count_matches_catalog(self):
        # Привязка к фактическому каталогу, а не к «магическому» числу.
        _, out = _run_types()
        rows = _parsed_lines(out)
        self.assertEqual(len(rows), len(CATALOG_TYPES))

    def test_every_line_has_four_fields(self):
        _, out = _run_types()
        for row in _parsed_lines(out):
            type_name, category, severity, regs = row
            self.assertTrue(type_name)
            self.assertTrue(category)
            self.assertTrue(severity)
            self.assertTrue(regs)

    def test_no_trailing_blank_garbage(self):
        # Каждая значимая строка начинается с отступа в два пробела.
        _, out = _run_types()
        for line in out.splitlines():
            if line.strip():
                self.assertTrue(line.startswith("  "))


class TypesSortingAndCoverageTests(unittest.TestCase):
    """Сортировка по типу и полнота покрытия каталога."""

    def test_types_sorted(self):
        _, out = _run_types()
        types = [r[0] for r in _parsed_lines(out)]
        self.assertEqual(types, sorted(types))

    def test_types_match_catalog_set(self):
        _, out = _run_types()
        types = [r[0] for r in _parsed_lines(out)]
        self.assertEqual(types, CATALOG_TYPES)

    def test_no_duplicate_types(self):
        _, out = _run_types()
        types = [r[0] for r in _parsed_lines(out)]
        self.assertEqual(len(types), len(set(types)))

    def test_known_types_present(self):
        _, out = _run_types()
        types = {r[0] for r in _parsed_lines(out)}
        for expected in ("EMAIL", "CREDIT_CARD", "AADHAAR", "AWS_SECRET_KEY"):
            self.assertIn(expected, types)


class TypesFieldsTests(unittest.TestCase):
    """Категория/критичность/регламенты совпадают с таксономией и compliance."""

    def setUp(self):
        _, out = _run_types()
        self.rows = {r[0]: r for r in _parsed_lines(out)}

    def test_every_category_matches_taxonomy(self):
        for type_name, (_, category, _sev, _regs) in self.rows.items():
            self.assertEqual(category, category_of(type_name))

    def test_every_severity_matches_taxonomy(self):
        for type_name, (_, _cat, severity, _regs) in self.rows.items():
            self.assertEqual(severity, severity_of(type_name))

    def test_every_regs_field_matches_compliance(self):
        for type_name, (_, _cat, _sev, regs) in self.rows.items():
            self.assertEqual(regs, _regs_field(type_name))

    def test_aadhaar_row(self):
        # AADHAAR: government_id / high, регламенты семейства GDPR (CCPA, GDPR, HIPAA).
        _, category, severity, regs = self.rows["AADHAAR"]
        self.assertEqual(category, "government_id")
        self.assertEqual(severity, "high")
        self.assertEqual(regs, "CCPA, GDPR, HIPAA")
        self.assertIn("GDPR", regs)

    def test_credit_card_row(self):
        # CREDIT_CARD: financial, переопределён до critical, среди регламентов PCI-DSS.
        _, category, severity, regs = self.rows["CREDIT_CARD"]
        self.assertEqual(category, "financial")
        self.assertEqual(severity, "critical")
        self.assertIn("PCI-DSS", regs)
        self.assertEqual(regs, "CCPA, GDPR, HIPAA, PCI-DSS")

    def test_secret_row_shows_dash_and_critical(self):
        # Секрет (category 'secret'): critical и «—» (никакой регламент не покрывает).
        _, category, severity, regs = self.rows["AWS_SECRET_KEY"]
        self.assertEqual(category, "secret")
        self.assertEqual(severity, "critical")
        self.assertEqual(regs, "—")

    def test_all_secrets_show_dash(self):
        # Любой тип категории 'secret' печатает «—» в поле регламентов.
        for type_name, (_, category, _sev, regs) in self.rows.items():
            if category == "secret":
                self.assertEqual(regs, "—", type_name)

    def test_non_secret_pii_has_regs(self):
        # Контактные/идентификационные типы имеют хотя бы один регламент.
        for type_name, (_, category, _sev, regs) in self.rows.items():
            if category in ("contact", "person", "government_id", "financial"):
                self.assertNotEqual(regs, "—", type_name)

    def test_pci_dss_only_for_financial(self):
        # PCI-DSS встречается только у financial-типов.
        for type_name, (_, category, _sev, regs) in self.rows.items():
            if "PCI-DSS" in regs.split(", "):
                self.assertEqual(category, "financial", type_name)


class ComplianceMappingTests(unittest.TestCase):
    """Прямые проверки datashield.compliance (источник полей регламентов)."""

    def test_regulations_keys(self):
        self.assertEqual(
            set(REGULATIONS), {"GDPR", "HIPAA", "PCI-DSS", "CCPA"}
        )

    def test_secret_maps_to_no_regulation(self):
        self.assertEqual(regulations_for("AWS_SECRET_KEY"), [])
        self.assertEqual(regulations_for("JWT"), [])

    def test_pci_dss_only_covers_financial(self):
        self.assertEqual(REGULATIONS["PCI-DSS"], {"financial"})

    def test_credit_card_regulations_sorted_with_pci(self):
        self.assertEqual(
            regulations_for("CREDIT_CARD"),
            ["CCPA", "GDPR", "HIPAA", "PCI-DSS"],
        )

    def test_aadhaar_regulations(self):
        self.assertEqual(regulations_for("AADHAAR"), ["CCPA", "GDPR", "HIPAA"])

    def test_regulations_for_is_sorted(self):
        regs = regulations_for("IBAN")
        self.assertEqual(regs, sorted(regs))

    def test_email_only_broad_pii_regs_no_pci(self):
        # EMAIL — contact, не financial → без PCI-DSS.
        self.assertNotIn("PCI-DSS", regulations_for("EMAIL"))

    def test_classify_groups_by_regulation(self):
        out = classify(["CREDIT_CARD", "AWS_SECRET_KEY", "EMAIL"])
        # Секрет не попадает ни в один регламент.
        for types in out.values():
            self.assertNotIn("AWS_SECRET_KEY", types)
        # PCI-DSS получает только CREDIT_CARD.
        self.assertEqual(out.get("PCI-DSS"), ["CREDIT_CARD"])
        # EMAIL присутствует у broad-PII-регламентов.
        self.assertIn("EMAIL", out["GDPR"])

    def test_classify_values_sorted(self):
        out = classify(["IBAN", "CREDIT_CARD"])
        for types in out.values():
            self.assertEqual(types, sorted(types))

    def test_classify_keys_sorted(self):
        out = classify(["CREDIT_CARD", "EMAIL"])
        self.assertEqual(list(out), sorted(out))

    def test_classify_secret_only_is_empty(self):
        self.assertEqual(classify(["AWS_SECRET_KEY", "JWT"]), {})


class TypesPluginDiscoveryTests(unittest.TestCase):
    """Обнаружение сторонних детекторов через монкипатч entry_points.

    Без установки пакетов: подменяем importlib.metadata.entry_points фейком.
    Хороший плагин должен появиться в выводе `types`; сломанный entry point —
    быть пропущен, не уронив команду.
    """

    def setUp(self):
        self._orig = _md.entry_points
        self.addCleanup(self._restore)

    def _restore(self):
        _md.entry_points = self._orig

    @staticmethod
    def _make_eps(eps):
        class FakeEntryPoint:
            def __init__(self, builder, name):
                self._builder = builder
                self.name = name

            def load(self):
                return self._builder

        class FakeEntryPoints:
            def __init__(self, items):
                self._items = items

            def select(self, group=None):
                if group == "datashield.detectors":
                    return self._items
                return []

        items = [FakeEntryPoint(b, n) for (b, n) in eps]
        return lambda: FakeEntryPoints(items)

    def test_good_plugin_appears_in_types_output(self):
        def good_builder():
            return [RegexDetector("acme", "ACME_TOKEN", r"ACME-\d+", 0.95)]

        _md.entry_points = self._make_eps([(good_builder, "acme")])
        _, out = _run_types()
        types = {r[0] for r in _parsed_lines(out)}
        self.assertIn("ACME_TOKEN", types)

    def test_good_plugin_increases_line_count(self):
        def good_builder():
            return [RegexDetector("acme", "ACME_TOKEN", r"ACME-\d+", 0.95)]

        # Базовая длина (без плагина) — 68.
        _md.entry_points = self._make_eps([(good_builder, "acme")])
        _, out = _run_types()
        self.assertEqual(len(_parsed_lines(out)), 69)

    def test_broken_entry_point_is_skipped(self):
        def broken_builder():
            raise RuntimeError("плагин сломан")

        _md.entry_points = self._make_eps([(broken_builder, "broken")])
        # Команда не падает и печатает ровно дефолтные 68 строк.
        code, out = _run_types()
        self.assertEqual(code, 0)
        self.assertEqual(len(_parsed_lines(out)), 68)

    def test_broken_does_not_block_good(self):
        def good_builder():
            return [RegexDetector("acme", "ACME_TOKEN", r"ACME-\d+", 0.95)]

        def broken_builder():
            raise RuntimeError("boom")

        _md.entry_points = self._make_eps(
            [(broken_builder, "broken"), (good_builder, "acme")]
        )
        code, out = _run_types()
        self.assertEqual(code, 0)
        types = {r[0] for r in _parsed_lines(out)}
        self.assertIn("ACME_TOKEN", types)

    def test_build_catalog_does_not_crash_on_broken(self):
        # Прямой контракт registry: сломанный EP не валит build_catalog.
        def broken_builder():
            raise RuntimeError("boom")

        _md.entry_points = self._make_eps([(broken_builder, "broken")])
        catalog = registry.build_catalog(Config())
        # 75 детекторов по умолчанию (сломанный плагин не добавлен).
        self.assertEqual(len(catalog), 75)


if __name__ == "__main__":
    unittest.main()
