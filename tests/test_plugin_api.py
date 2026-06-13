"""Тесты публичного plugin API детекторов Data Shield AI.

ФОКУС: datashield.detectors.registry._plugin_detectors() и интеграция сторонних
детекторов в build_catalog()/scan().

Контракт (по реальному источнику registry.py):
- Сторонние детекторы грузятся через importlib.metadata entry_points группы
  "datashield.detectors". Каждый entry point — zero-arg callable (builder),
  возвращающий список детекторов.
- Без плагинов _plugin_detectors() -> [].
- Поддерживаются обе формы API entry_points(): новая (.select(group=...)) и
  легаси-словарь (eps.get(group, [])).
- Плагин-детекторы добавляются в каталог как default_enabled=True, поэтому
  попадают в активный набор без явного включения.
- Битый плагин (builder бросает при вызове) и EP, чей .load() бросает, —
  ОБА пропускаются, не роняя build_catalog; прочие детекторы остаются.
- Если сам entry_points() бросает — discovery возвращает [].

Плагины НЕ устанавливаются через pip: мы монкипатчим
importlib.metadata.entry_points фейком в каждом тесте и аккуратно
восстанавливаем оригинал в tearDown/finally.
"""
import importlib.metadata as _md
import unittest

from datashield import Config, redact, scan
from datashield.detectors import registry
from datashield.detectors.base import Finding, RegexDetector

# --- Фейковая инфраструктура entry points -----------------------------------

GROUP = "datashield.detectors"

# Базовые размеры встроенного каталога (без плагинов), вычисленные в момент
# запуска — чтобы ассерты не ломались при добавлении новых детекторов.
_BASELINE_CATALOG = registry.build_catalog(Config())
DETECTOR_COUNT = len(_BASELINE_CATALOG)
DEFAULT_ON_COUNT = sum(1 for i in _BASELINE_CATALOG if i.default_enabled)
TYPE_COUNT = len({i.detector.type for i in _BASELINE_CATALOG})


def _widget_builder():
    """Builder, возвращающий один кастомный RegexDetector."""
    return [RegexDetector("widget_id", "WIDGET_ID", r"WIDGET-\d{4}", 0.99)]


def _two_builder():
    """Builder, возвращающий два детектора сразу."""
    return [
        RegexDetector("alpha_det", "ALPHA", r"ALPHA-\d+", 0.95),
        RegexDetector("beta_det", "BETA", r"BETA-\d+", 0.95),
    ]


def _raising_builder():
    """Builder, который бросает при ВЫЗОВЕ (а не при .load())."""
    raise RuntimeError("плагин сломан при построении")


class FakeEntryPoint:
    """Имитирует importlib.metadata.EntryPoint: имеет .group и .load()."""

    def __init__(self, loader, *, name="fake", group=GROUP, load_raises=False):
        self.name = name
        self.group = group
        self._loader = loader
        self._load_raises = load_raises

    def load(self):
        if self._load_raises:
            raise ImportError("не удалось импортировать плагин")
        return self._loader


class SelectEntryPoints:
    """Новая форма API: объект с методом .select(group=...)."""

    def __init__(self, eps):
        self._eps = list(eps)

    def select(self, group=None):
        return [ep for ep in self._eps if ep.group == group]


class LegacyEntryPoints(dict):
    """Легаси-форма API: обычный dict группа -> список EP (без .select)."""


def _make_select_factory(eps):
    def factory():
        return SelectEntryPoints(eps)

    return factory


def _make_legacy_factory(eps):
    def factory():
        return LegacyEntryPoints({GROUP: list(eps)})

    return factory


class _PatchEntryPointsMixin:
    """Подменяет importlib.metadata.entry_points и восстанавливает в tearDown."""

    def setUp(self):
        self._orig_entry_points = _md.entry_points

    def tearDown(self):
        _md.entry_points = self._orig_entry_points

    def patch(self, factory):
        # _plugin_detectors делает локальный `from importlib.metadata import
        # entry_points`, поэтому патчим атрибут модуля importlib.metadata.
        _md.entry_points = factory


# --- Базовое поведение без плагинов -----------------------------------------


class NoPluginsTests(unittest.TestCase):
    """Без сторонних плагинов discovery пуст, каталог не меняется."""

    def test_plugin_detectors_empty_by_default(self):
        # В тестовом окружении нет пакетов с группой datashield.detectors.
        self.assertEqual(registry._plugin_detectors(), [])

    def test_plugin_detectors_returns_list(self):
        self.assertIsInstance(registry._plugin_detectors(), list)

    def test_catalog_counts_unchanged(self):
        cat = registry.build_catalog(Config())
        self.assertEqual(len(cat), DETECTOR_COUNT)
        self.assertEqual(sum(1 for c in cat if c.default_enabled), DEFAULT_ON_COUNT)
        self.assertEqual(len({c.detector.type for c in cat}), TYPE_COUNT)


# --- Новая форма API: .select(group=) ---------------------------------------


class SelectApiPluginTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Загрузка плагина через объект entry_points с .select(group=...)."""

    def setUp(self):
        super().setUp()
        self.patch(_make_select_factory([FakeEntryPoint(_widget_builder)]))

    def test_plugin_detector_discovered(self):
        dets = registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["WIDGET_ID"])

    def test_plugin_detector_is_regex_detector(self):
        (det,) = registry._plugin_detectors()
        self.assertIsInstance(det, RegexDetector)
        self.assertEqual(det.name, "widget_id")

    def test_plugin_in_catalog(self):
        cat = registry.build_catalog(Config())
        names = {c.detector.name for c in cat}
        self.assertIn("widget_id", names)

    def test_plugin_default_enabled_true(self):
        # _plugin_detectors добавляются как (d, True) -> default_enabled True.
        cat = registry.build_catalog(Config())
        info = next(c for c in cat if c.detector.name == "widget_id")
        self.assertTrue(info.default_enabled)
        self.assertTrue(info.enabled)

    def test_plugin_grows_catalog_by_one(self):
        # Встроенные детекторы + 1 плагин.
        self.assertEqual(len(registry.build_catalog(Config())), DETECTOR_COUNT + 1)

    def test_plugin_in_active_set(self):
        actives = registry.build_active(Config())
        names = {d.name for d in actives}
        self.assertIn("widget_id", names)

    def test_scan_uses_plugin_detector(self):
        out = scan("ticket WIDGET-1234 closed")
        types = {f.type for f in out}
        self.assertIn("WIDGET_ID", types)

    def test_scan_plugin_finding_shape(self):
        out = scan("WIDGET-1234")
        widgets = [f for f in out if f.type == "WIDGET_ID"]
        self.assertEqual(len(widgets), 1)
        f = widgets[0]
        self.assertIsInstance(f, Finding)
        self.assertEqual(f.value, "WIDGET-1234")
        self.assertEqual(f.detector, "widget_id")

    def test_redact_masks_plugin_value(self):
        result = redact("ref WIDGET-1234 here")
        self.assertNotIn("WIDGET-1234", result.masked_text)
        self.assertIn("[WIDGET_ID_1]", result.masked_text)


# --- Легаси форма API: dict.get(group, []) ----------------------------------


class LegacyApiPluginTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Загрузка плагина через легаси-словарь entry_points (без .select)."""

    def setUp(self):
        super().setUp()
        self.patch(_make_legacy_factory([FakeEntryPoint(_widget_builder)]))

    def test_no_select_attribute(self):
        # Удостоверяемся, что фейк действительно идёт по легаси-ветке.
        eps = _md.entry_points()
        self.assertFalse(hasattr(eps, "select"))

    def test_plugin_detector_discovered(self):
        dets = registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["WIDGET_ID"])

    def test_plugin_in_catalog(self):
        names = {c.detector.name for c in registry.build_catalog(Config())}
        self.assertIn("widget_id", names)

    def test_scan_uses_plugin_detector(self):
        types = {f.type for f in scan("see WIDGET-4321")}
        self.assertIn("WIDGET_ID", types)


# --- Несколько детекторов из одного builder ---------------------------------


class MultiDetectorBuilderTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Builder может вернуть несколько детекторов — все попадают в каталог."""

    def setUp(self):
        super().setUp()
        self.patch(_make_select_factory([FakeEntryPoint(_two_builder)]))

    def test_both_detectors_discovered(self):
        types = {d.type for d in registry._plugin_detectors()}
        self.assertEqual(types, {"ALPHA", "BETA"})

    def test_both_in_active_set(self):
        names = {d.name for d in registry.build_active(Config())}
        self.assertIn("alpha_det", names)
        self.assertIn("beta_det", names)

    def test_scan_finds_both(self):
        types = {f.type for f in scan("ALPHA-1 and BETA-2")}
        self.assertIn("ALPHA", types)
        self.assertIn("BETA", types)


# --- Изоляция ошибок: битый плагин не валит остальные ------------------------


class BrokenPluginIsolationTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Builder, бросающий при вызове, пропускается — прочие детекторы живут."""

    def setUp(self):
        super().setUp()
        eps = [
            FakeEntryPoint(_raising_builder, name="broken"),
            FakeEntryPoint(_widget_builder, name="ok"),
        ]
        self.patch(_make_select_factory(eps))

    def test_broken_builder_skipped_good_kept(self):
        dets = registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["WIDGET_ID"])

    def test_build_catalog_does_not_crash(self):
        cat = registry.build_catalog(Config())  # не должно бросать
        names = {c.detector.name for c in cat}
        self.assertIn("widget_id", names)

    def test_builtin_detectors_still_present(self):
        # Встроенный EMAIL остаётся, несмотря на битый плагин.
        cat = registry.build_catalog(Config())
        types = {c.detector.type for c in cat}
        self.assertIn("EMAIL", types)

    def test_scan_still_works(self):
        out = scan("write to user@example.com about WIDGET-1234")
        types = {f.type for f in out}
        self.assertIn("EMAIL", types)
        self.assertIn("WIDGET_ID", types)


class LoadRaisesIsolationTests(_PatchEntryPointsMixin, unittest.TestCase):
    """EP, чей .load() бросает, пропускается — прочие детекторы живут."""

    def setUp(self):
        super().setUp()
        eps = [
            FakeEntryPoint(None, name="cant_load", load_raises=True),
            FakeEntryPoint(_widget_builder, name="ok"),
        ]
        self.patch(_make_select_factory(eps))

    def test_load_error_skipped_good_kept(self):
        dets = registry._plugin_detectors()
        self.assertEqual([d.type for d in dets], ["WIDGET_ID"])

    def test_build_catalog_does_not_crash(self):
        names = {c.detector.name for c in registry.build_catalog(Config())}
        self.assertIn("widget_id", names)

    def test_scan_still_works(self):
        types = {f.type for f in scan("WIDGET-1234")}
        self.assertIn("WIDGET_ID", types)


class AllPluginsBrokenTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Когда ВСЕ плагины битые — discovery пуст, но не падает."""

    def setUp(self):
        super().setUp()
        eps = [
            FakeEntryPoint(_raising_builder, name="b1"),
            FakeEntryPoint(None, name="b2", load_raises=True),
        ]
        self.patch(_make_select_factory(eps))

    def test_plugin_detectors_empty(self):
        self.assertEqual(registry._plugin_detectors(), [])

    def test_catalog_back_to_baseline(self):
        self.assertEqual(len(registry.build_catalog(Config())), DETECTOR_COUNT)

    def test_builtin_scan_unaffected(self):
        types = {f.type for f in scan("user@example.com")}
        self.assertIn("EMAIL", types)


# --- Сбой самого discovery (entry_points() бросает) -------------------------


class DiscoveryFailureTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Если entry_points() бросает целиком — discovery возвращает []."""

    def setUp(self):
        super().setUp()

        def raising_entry_points():
            raise RuntimeError("discovery упал")

        self.patch(raising_entry_points)

    def test_plugin_detectors_empty(self):
        self.assertEqual(registry._plugin_detectors(), [])

    def test_build_catalog_unaffected(self):
        self.assertEqual(len(registry.build_catalog(Config())), DETECTOR_COUNT)


class SelectRaisesTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Если .select(group=...) бросает — discovery возвращает []."""

    def setUp(self):
        super().setUp()

        class BadSelect:
            def select(self, group=None):
                raise RuntimeError("select упал")

        self.patch(lambda: BadSelect())

    def test_plugin_detectors_empty(self):
        self.assertEqual(registry._plugin_detectors(), [])


# --- Включение плагина через Config (enable override) -----------------------


class PluginEnabledViaConfigTests(_PatchEntryPointsMixin, unittest.TestCase):
    """Плагин можно выключить через disabled_detectors и снова включить."""

    def setUp(self):
        super().setUp()
        self.patch(_make_select_factory([FakeEntryPoint(_widget_builder)]))

    def test_disabled_via_config_name(self):
        cfg = Config(disabled_detectors=("widget_id",))
        info = next(
            c for c in registry.build_catalog(cfg) if c.detector.name == "widget_id"
        )
        self.assertFalse(info.enabled)

    def test_disabled_via_config_type(self):
        cfg = Config(disabled_detectors=("WIDGET_ID",))
        info = next(
            c for c in registry.build_catalog(cfg) if c.detector.name == "widget_id"
        )
        self.assertFalse(info.enabled)

    def test_disabled_plugin_not_in_active(self):
        cfg = Config(disabled_detectors=("WIDGET_ID",))
        names = {d.name for d in registry.build_active(cfg)}
        self.assertNotIn("widget_id", names)

    def test_disabled_plugin_not_scanned(self):
        cfg = Config(disabled_detectors=("WIDGET_ID",))
        types = {f.type for f in scan("WIDGET-1234", config=cfg)}
        self.assertNotIn("WIDGET_ID", types)

    def test_re_enable_via_enabled_override(self):
        # enabled_detectors имеет приоритет над disabled (см. build_catalog).
        cfg = Config(
            disabled_detectors=("WIDGET_ID",),
            enabled_detectors=("WIDGET_ID",),
        )
        info = next(
            c for c in registry.build_catalog(cfg) if c.detector.name == "widget_id"
        )
        self.assertTrue(info.enabled)


# --- Интеграция плагина с compliance в report() -----------------------------


class PluginComplianceTests(_PatchEntryPointsMixin, unittest.TestCase):
    """report().compliance учитывает типы плагинов через taxonomy/compliance."""

    def setUp(self):
        super().setUp()

    def test_unknown_plugin_type_maps_to_no_regulation(self):
        # WIDGET_ID нет в таксономии -> категория 'other' -> ни один регламент.
        self.patch(_make_select_factory([FakeEntryPoint(_widget_builder)]))
        report = redact("WIDGET-1234").report()
        self.assertIn("compliance", report)
        self.assertNotIn(
            "WIDGET_ID",
            {t for types in report["compliance"].values() for t in types},
        )

    def test_plugin_reusing_known_type_inherits_regulations(self):
        # Плагин, выдающий тип CREDIT_CARD, наследует его регламенты
        # (financial -> все четыре, включая PCI-DSS).
        def cc_builder():
            # Узнаваемая тестовая карта Visa (проходит Luhn в нашей таксономии
            # как тип CREDIT_CARD по имени типа, без валидатора).
            return [RegexDetector("cc_plugin", "CREDIT_CARD", r"CARD-(\d+)", 0.99,
                                  group=1)]

        self.patch(_make_select_factory([FakeEntryPoint(cc_builder)]))
        report = redact("payment CARD-4111111111111111 ok").report()
        comp = report["compliance"]
        self.assertIn("PCI-DSS", comp)
        self.assertIn("CREDIT_CARD", comp["PCI-DSS"])
        for reg in ("GDPR", "HIPAA", "CCPA"):
            self.assertIn("CREDIT_CARD", comp[reg])


if __name__ == "__main__":
    unittest.main()
