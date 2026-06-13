"""Интеграционные тесты регуляторного слоя (Block H).

Проверяют сквозное поведение: документы под каждый регламент → группировка в
report()["compliance"]; согласованность regulations_for с таксономией для ВСЕХ
типов каталога; PCI-DSS == ровно financial-типы; секреты не относятся ни к
одному регламенту. Также — обнаружение сторонних детекторов через
монкипатч importlib.metadata.entry_points (без установки пакетов).

Тесты утверждают ФАКТИЧЕСКОЕ поведение исходников, не желаемое.
"""
import importlib.metadata as _md
import unittest

from datashield import redact
from datashield.compliance import REGULATIONS, classify, regulations_for
from datashield.config import Config
from datashield.detectors import registry as _registry
from datashield.detectors.base import RegexDetector
from datashield.detectors.registry import build_catalog
from datashield.taxonomy import category_of


def _catalog_types(config=None):
    return sorted({i.detector.type for i in build_catalog(config or Config())})


CATALOG_TYPES = _catalog_types()

# Базовые размеры каталога, вычисленные в момент запуска: число детекторов,
# число включённых по умолчанию и число различных типов. Вычисляются из живого
# каталога, чтобы ассерты не ломались при добавлении новых детекторов.
_BASELINE_CATALOG = build_catalog(Config())
DETECTOR_COUNT = len(_BASELINE_CATALOG)
DEFAULT_ON_COUNT = sum(1 for i in _BASELINE_CATALOG if i.default_enabled)
TYPE_COUNT = len(CATALOG_TYPES)


# --------------------------------------------------------------------------
# Форма каталога: число детекторов / включённых по умолчанию / различных типов.
# Текущие значения (на момент написания): 90 детекторов / 86 по умолчанию /
# 83 типа. Сверяем с динамически вычисленной базовой линией.
# --------------------------------------------------------------------------
class CatalogShapeTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_catalog(Config())

    def test_detector_count_matches_baseline(self):
        self.assertEqual(len(self.catalog), DETECTOR_COUNT)

    def test_default_on_count_matches_baseline(self):
        self.assertEqual(
            sum(1 for i in self.catalog if i.default_enabled), DEFAULT_ON_COUNT
        )

    def test_distinct_type_count_matches_baseline(self):
        self.assertEqual(len(CATALOG_TYPES), TYPE_COUNT)


# --------------------------------------------------------------------------
# Структура REGULATIONS из исходника (REGULATIONS {GDPR,HIPAA,PCI-DSS,CCPA}).
# --------------------------------------------------------------------------
class RegulationsStructureTests(unittest.TestCase):
    def test_exactly_four_regulations(self):
        self.assertEqual(
            set(REGULATIONS), {"GDPR", "HIPAA", "PCI-DSS", "CCPA"}
        )

    def test_pci_covers_only_financial_category(self):
        self.assertEqual(REGULATIONS["PCI-DSS"], {"financial"})

    def test_secret_category_in_no_regulation(self):
        for reg, cats in REGULATIONS.items():
            self.assertNotIn("secret", cats, msg=reg)

    def test_every_regulation_maps_to_a_set(self):
        for reg, cats in REGULATIONS.items():
            self.assertIsInstance(cats, set, msg=reg)


# --------------------------------------------------------------------------
# regulations_for согласован с category_of для ВСЕХ типов каталога:
# каждый тип отображается ровно на регламенты, подразумеваемые его категорией.
# --------------------------------------------------------------------------
class RegulationsForConsistencyTests(unittest.TestCase):
    def test_regulations_for_matches_category_for_all_catalog_types(self):
        for type_name in CATALOG_TYPES:
            cat = category_of(type_name)
            expected = sorted(
                reg for reg, cats in REGULATIONS.items() if cat in cats
            )
            self.assertEqual(
                regulations_for(type_name),
                expected,
                msg=f"{type_name} (category={cat})",
            )

    def test_regulations_for_returns_sorted_list(self):
        for type_name in CATALOG_TYPES:
            regs = regulations_for(type_name)
            self.assertIsInstance(regs, list)
            self.assertEqual(regs, sorted(regs), msg=type_name)

    def test_secret_types_map_to_no_regulation(self):
        # Категория 'secret' не относится ни к одному регламенту.
        secret_types = [
            t for t in CATALOG_TYPES if category_of(t) == "secret"
        ]
        self.assertTrue(secret_types)  # секреты в каталоге есть
        for type_name in secret_types:
            self.assertEqual(regulations_for(type_name), [], msg=type_name)

    def test_unknown_type_maps_to_no_regulation(self):
        # Неизвестный тип → категория 'other' → пустой список.
        self.assertEqual(category_of("NOT_A_REAL_TYPE"), "other")
        self.assertEqual(regulations_for("NOT_A_REAL_TYPE"), [])


# --------------------------------------------------------------------------
# PCI-DSS покрывает РОВНО financial-типы каталога.
# --------------------------------------------------------------------------
class PciDssExactlyFinancialTests(unittest.TestCase):
    def setUp(self):
        self.financial_catalog = sorted(
            t for t in CATALOG_TYPES if category_of(t) == "financial"
        )

    def test_known_financial_catalog_types(self):
        # Зафиксированный список financial-типов в каталоге.
        self.assertEqual(
            self.financial_catalog,
            [
                "ABA_ROUTING",
                "BANK_ACCOUNT",
                "BIC",
                "CREDIT_CARD",
                "IBAN",
                "UK_SORT_CODE",
            ],
        )

    def test_pci_classify_equals_financial_set(self):
        # classify по всем типам каталога: множество PCI-DSS == financial-типы.
        pci = classify(CATALOG_TYPES).get("PCI-DSS", [])
        self.assertEqual(set(pci), set(self.financial_catalog))

    def test_each_financial_type_lists_pci(self):
        for type_name in self.financial_catalog:
            self.assertIn("PCI-DSS", regulations_for(type_name), msg=type_name)

    def test_no_nonfinancial_type_lists_pci(self):
        for type_name in CATALOG_TYPES:
            if category_of(type_name) != "financial":
                self.assertNotIn(
                    "PCI-DSS", regulations_for(type_name), msg=type_name
                )


# --------------------------------------------------------------------------
# classify(): группировка типов по регламентам, сортировка, дедупликация.
# --------------------------------------------------------------------------
class ClassifyContractTests(unittest.TestCase):
    def test_empty_input_returns_empty_dict(self):
        self.assertEqual(classify([]), {})

    def test_secrets_only_yields_empty_dict(self):
        secret_types = [
            t for t in CATALOG_TYPES if category_of(t) == "secret"
        ]
        self.assertEqual(classify(secret_types), {})

    def test_values_are_sorted_lists(self):
        result = classify(["US_SSN", "EMAIL", "IP", "CREDIT_CARD"])
        for reg, types in result.items():
            self.assertEqual(types, sorted(types), msg=reg)

    def test_keys_are_sorted(self):
        result = classify(["CREDIT_CARD", "EMAIL"])
        self.assertEqual(list(result.keys()), sorted(result.keys()))

    def test_dedupes_repeated_types(self):
        # Список с повторами и множество дают одинаковый результат.
        self.assertEqual(
            classify(["EMAIL", "EMAIL", "EMAIL"]), classify({"EMAIL"})
        )

    def test_each_type_grouped_under_its_regulations(self):
        # Каждый тип попадает ровно в те регламенты, что вернул regulations_for.
        types = ["EMAIL", "CREDIT_CARD", "US_SSN", "IP"]
        result = classify(types)
        for type_name in types:
            for reg in regulations_for(type_name):
                self.assertIn(type_name, result[reg], msg=(reg, type_name))


# --------------------------------------------------------------------------
# Сквозной отчёт: report()["compliance"] == classify({найденные типы}).
# Документы строятся так, чтобы реально сработали детекторы.
# --------------------------------------------------------------------------
class ReportComplianceEndToEndTests(unittest.TestCase):
    def _report(self, text):
        return redact(text).report()

    def test_report_always_has_compliance_key(self):
        self.assertIn("compliance", self._report("просто текст без данных"))

    def test_clean_text_has_empty_compliance(self):
        self.assertEqual(self._report("просто текст без данных")["compliance"], {})

    def test_compliance_equals_classify_of_found_types(self):
        # Главный инвариант: compliance == classify по фактически найденным типам.
        doc = (
            "email a@b.com card 4111 1111 1111 1111 "
            "ip 10.0.0.5 ssn 123-45-6789"
        )
        result = redact(doc)
        found = {f.type for f in result.findings}
        self.assertEqual(
            result.report()["compliance"], classify(found)
        )

    def test_email_doc_groups_into_broad_pii_regs(self):
        # contact (email) покрывают GDPR/CCPA/HIPAA, но не PCI-DSS.
        report = self._report("пиши на john.doe@example.com")
        comp = report["compliance"]
        self.assertEqual(set(comp), {"GDPR", "CCPA", "HIPAA"})
        for reg in ("GDPR", "CCPA", "HIPAA"):
            self.assertIn("EMAIL", comp[reg])
        self.assertNotIn("PCI-DSS", comp)

    def test_credit_card_doc_includes_pci(self):
        # financial (карта) добавляет PCI-DSS поверх широких PII-регламентов.
        comp = self._report("оплата картой 4111 1111 1111 1111")["compliance"]
        self.assertEqual(set(comp), {"GDPR", "CCPA", "HIPAA", "PCI-DSS"})
        self.assertEqual(comp["PCI-DSS"], ["CREDIT_CARD"])

    def test_iban_doc_includes_pci(self):
        comp = self._report("счёт IBAN DE89 3704 0044 0532 0130 00")["compliance"]
        self.assertIn("PCI-DSS", comp)
        self.assertEqual(comp["PCI-DSS"], ["IBAN"])

    def test_network_doc_no_pci(self):
        comp = self._report("сервер 192.168.1.100")["compliance"]
        self.assertEqual(set(comp), {"GDPR", "CCPA", "HIPAA"})
        self.assertNotIn("PCI-DSS", comp)

    def test_government_id_doc_no_pci(self):
        comp = self._report("SSN 123-45-6789")["compliance"]
        self.assertEqual(set(comp), {"GDPR", "CCPA", "HIPAA"})
        for reg in ("GDPR", "CCPA", "HIPAA"):
            self.assertIn("US_SSN", comp[reg])

    def test_crypto_doc_only_gdpr(self):
        # crypto покрывает только GDPR (см. REGULATIONS).
        result = redact("кошелёк 0x" + "a" * 40)
        self.assertIn("ETH_ADDRESS", result.stats)
        comp = result.report()["compliance"]
        self.assertEqual(set(comp), {"GDPR"})
        self.assertEqual(comp["GDPR"], ["ETH_ADDRESS"])

    def test_health_doc_gdpr_and_hipaa(self):
        # health покрывают GDPR и HIPAA (но не CCPA, не PCI-DSS).
        result = redact("полис ОМС 1234567890123456")
        self.assertIn("OMS_POLICY", result.stats)
        comp = result.report()["compliance"]
        self.assertEqual(set(comp), {"GDPR", "HIPAA"})
        for reg in ("GDPR", "HIPAA"):
            self.assertIn("OMS_POLICY", comp[reg])

    def test_secret_only_doc_empty_compliance_but_has_findings(self):
        # Секрет найден (есть finding), но ни в один регламент не попадает.
        result = redact("ключ sk-ant-api03-" + "a" * 95)
        self.assertTrue(result.findings)  # секрет реально обнаружен
        self.assertIn("ANTHROPIC_KEY", result.stats)
        self.assertEqual(result.report()["compliance"], {})

    def test_multi_reg_doc_groups_each_type_correctly(self):
        # Документ со всеми «семьями» данных: проверяем, что каждый тип лёг в
        # свои регламенты согласно regulations_for.
        doc = (
            "email a@b.com card 4111 1111 1111 1111 ip 10.0.0.5 "
            "ssn 123-45-6789 wallet 0x" + "a" * 40
        )
        result = redact(doc)
        comp = result.report()["compliance"]
        for type_name in result.stats:
            for reg in regulations_for(type_name):
                self.assertIn(type_name, comp[reg], msg=(reg, type_name))
        # PCI-DSS содержит только финансовый тип из документа.
        self.assertEqual(comp.get("PCI-DSS"), ["CREDIT_CARD"])

    def test_report_compliance_values_are_sorted(self):
        doc = "card 4111 1111 1111 1111 email a@b.com ip 10.0.0.5"
        comp = redact(doc).report()["compliance"]
        for reg, types in comp.items():
            self.assertEqual(types, sorted(types), msg=reg)


# --------------------------------------------------------------------------
# Обнаружение сторонних детекторов через entry_points (монкипатч, без pip).
# Цель: убедиться, что _plugin_detectors реально вызывает entry_points и что
# битый плагин пропускается, не роняя build_catalog.
# --------------------------------------------------------------------------
class _FakeEP:
    """Минимальный заглушечный entry point: .load() → callable-сборщик."""

    def __init__(self, builder):
        self._builder = builder

    def load(self):
        return self._builder


class _SelectableEPs:
    """Имитирует современный API entry_points() с .select(group=...)."""

    def __init__(self, eps):
        self._eps = eps

    def select(self, group):
        if group == "datashield.detectors":
            return list(self._eps)
        return []


class _LegacyEPs(dict):
    """Имитирует устаревший dict-стиль entry_points() (без .select)."""


def _good_builder():
    return [RegexDetector("ptest", "PLUGIN_TYPE", r"PLUGINMARKER", 0.99)]


def _broken_builder():
    raise RuntimeError("плагин сломан")


class PluginDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self._orig_entry_points = _md.entry_points
        self.addCleanup(self._restore)

    def _restore(self):
        _md.entry_points = self._orig_entry_points

    def _patch(self, eps_obj):
        # _plugin_detectors делает `from importlib.metadata import entry_points`
        # внутри функции, поэтому патчим атрибут модуля importlib.metadata.
        _md.entry_points = lambda: eps_obj

    def test_good_plugin_detector_loaded(self):
        self._patch(_SelectableEPs([_FakeEP(_good_builder)]))
        dets = _registry._plugin_detectors()
        self.assertEqual([(d.name, d.type) for d in dets], [("ptest", "PLUGIN_TYPE")])

    def test_good_plugin_type_enters_catalog(self):
        self._patch(_SelectableEPs([_FakeEP(_good_builder)]))
        types = {i.detector.type for i in build_catalog(Config())}
        self.assertIn("PLUGIN_TYPE", types)

    def test_plugin_detector_default_enabled(self):
        # Плагин-детекторы добавляются как default_enabled=True.
        self._patch(_SelectableEPs([_FakeEP(_good_builder)]))
        info = next(
            i for i in build_catalog(Config()) if i.detector.type == "PLUGIN_TYPE"
        )
        self.assertTrue(info.default_enabled)
        self.assertTrue(info.enabled)

    def test_broken_plugin_skipped_not_crashing(self):
        # Битый entry point пропускается, остальные плагины загружаются.
        self._patch(
            _SelectableEPs([_FakeEP(_broken_builder), _FakeEP(_good_builder)])
        )
        dets = _registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["PLUGIN_TYPE"])

    def test_broken_plugin_does_not_break_build_catalog(self):
        self._patch(_SelectableEPs([_FakeEP(_broken_builder)]))
        # Не должно бросать исключений и каталог сохраняет базовую форму.
        catalog = build_catalog(Config())
        self.assertEqual(len(catalog), DETECTOR_COUNT)
        types = {i.detector.type for i in catalog}
        self.assertEqual(len(types), TYPE_COUNT)
        self.assertNotIn("PLUGIN_TYPE", types)

    def test_legacy_dict_entry_points_path(self):
        # Устаревший API без .select: используется ветка eps.get(...).
        legacy = _LegacyEPs()
        legacy["datashield.detectors"] = [_FakeEP(_good_builder)]
        self._patch(legacy)
        dets = _registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["PLUGIN_TYPE"])

    def test_entry_points_discovery_exception_returns_empty(self):
        # Если сам entry_points() падает — discovery возвращает [], не падает.
        def _boom():
            raise RuntimeError("discovery failed")

        _md.entry_points = _boom
        self.assertEqual(_registry._plugin_detectors(), [])

    def test_no_plugins_returns_empty(self):
        self._patch(_SelectableEPs([]))
        self.assertEqual(_registry._plugin_detectors(), [])

    def test_plugin_findings_flow_through_redact(self):
        # Сквозь redact(): плагин-детектор реально маскирует свой маркер.
        self._patch(_SelectableEPs([_FakeEP(_good_builder)]))
        result = redact("значение PLUGINMARKER в тексте")
        self.assertIn("PLUGIN_TYPE", result.stats)
        self.assertNotIn("PLUGINMARKER", result.masked_text)

    def test_catalog_restored_after_unpatch(self):
        # Контрольный кейс: после восстановления entry_points каталог = TYPE_COUNT.
        self._patch(_SelectableEPs([_FakeEP(_good_builder)]))
        self.assertIn("PLUGIN_TYPE", {i.detector.type for i in build_catalog(Config())})
        self._restore()
        self.assertEqual(len(_catalog_types()), TYPE_COUNT)


if __name__ == "__main__":
    unittest.main()
