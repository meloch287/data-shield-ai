"""Тесты опциональных плагинов ml_plugin и gliner_plugin при ОТСУТСТВИИ
пакетов presidio / gliner.

Сценарий: ни presidio_analyzer, ни gliner не установлены. Тогда детектор должен:
- не падать при detect() — возвращать [];
- после первого detect() пометить себя недоступным (available is False) и
  сохранить непустой load_error;
- не ломать публичные scan()/redact(), а при включении через
  Config(enabled_detectors=("ml",)/("gliner",)) просто не добавлять находок.

Эти тесты осмысленны только когда соответствующий пакет действительно
отсутствует в окружении. Если вдруг presidio/gliner установлены — кейсы,
завязанные на «недоступность», пропускаются (skip), чтобы не давать ложных
падений.
"""
import unittest

from datashield import Config, redact, scan, build_engine, Finding
from datashield.detectors import ml_plugin, gliner_plugin
from datashield.detectors.ml_plugin import MlDetector, build_optional as ml_build_optional
from datashield.detectors.gliner_plugin import (
    GlinerDetector,
    build_optional as gliner_build_optional,
)


# --- Определяем фактическую доступность тяжёлых пакетов в окружении. ---

def _module_importable(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


PRESIDIO_PRESENT = _module_importable("presidio_analyzer")
GLINER_PRESENT = _module_importable("gliner")

# Текст без свободных персональных данных — даже если бы модель загрузилась,
# тут нечего находить. Но основной упор кейсов — на режим «пакет отсутствует».
CLEAN_TEXT = "the quarterly numbers improved and the build is green"


class MlBuildOptionalTests(unittest.TestCase):
    """build_optional() ML-плагина: ровно один детектор с нужными атрибутами."""

    def test_returns_list(self):
        built = ml_build_optional()
        self.assertIsInstance(built, list)

    def test_returns_exactly_one_detector(self):
        self.assertEqual(len(ml_build_optional()), 1)

    def test_detector_is_ml_detector(self):
        (det,) = ml_build_optional()
        self.assertIsInstance(det, MlDetector)

    def test_detector_has_name(self):
        (det,) = ml_build_optional()
        self.assertEqual(det.name, "ml")

    def test_detector_has_type(self):
        (det,) = ml_build_optional()
        self.assertEqual(det.type, "PERSON")

    def test_detector_has_detect_callable(self):
        (det,) = ml_build_optional()
        self.assertTrue(callable(det.detect))

    def test_fresh_instances_are_distinct(self):
        # Каждый вызов строит новый экземпляр — состояние не разделяется.
        a = ml_build_optional()[0]
        b = ml_build_optional()[0]
        self.assertIsNot(a, b)


class GlinerBuildOptionalTests(unittest.TestCase):
    """build_optional() GLiNER-плагина: ровно один детектор с нужными атрибутами."""

    def test_returns_list(self):
        built = gliner_build_optional()
        self.assertIsInstance(built, list)

    def test_returns_exactly_one_detector(self):
        self.assertEqual(len(gliner_build_optional()), 1)

    def test_detector_is_gliner_detector(self):
        (det,) = gliner_build_optional()
        self.assertIsInstance(det, GlinerDetector)

    def test_detector_has_name(self):
        (det,) = gliner_build_optional()
        self.assertEqual(det.name, "gliner")

    def test_detector_has_type(self):
        (det,) = gliner_build_optional()
        self.assertEqual(det.type, "PERSON")

    def test_detector_has_detect_callable(self):
        (det,) = gliner_build_optional()
        self.assertTrue(callable(det.detect))

    def test_fresh_instances_are_distinct(self):
        a = gliner_build_optional()[0]
        b = gliner_build_optional()[0]
        self.assertIsNot(a, b)


class MlDetectorInitialStateTests(unittest.TestCase):
    """Состояние свежесозданного ML-детектора до первого detect()."""

    def setUp(self):
        self.det = MlDetector()

    def test_available_starts_true(self):
        # До ленивой загрузки детектор оптимистично считает себя доступным.
        self.assertTrue(self.det.available)

    def test_load_error_starts_none(self):
        self.assertIsNone(self.det.load_error)

    def test_not_loaded_initially(self):
        self.assertFalse(self.det._loaded)

    def test_analyzer_is_none_initially(self):
        self.assertIsNone(self.det._analyzer)

    def test_default_language_en(self):
        self.assertEqual(self.det.language, "en")

    def test_default_confidence(self):
        self.assertEqual(self.det.confidence, 0.85)

    def test_custom_params(self):
        det = MlDetector(language="ru", confidence=0.6)
        self.assertEqual(det.language, "ru")
        self.assertEqual(det.confidence, 0.6)


class GlinerDetectorInitialStateTests(unittest.TestCase):
    """Состояние свежесозданного GLiNER-детектора до первого detect()."""

    def setUp(self):
        self.det = GlinerDetector()

    def test_available_starts_true(self):
        self.assertTrue(self.det.available)

    def test_load_error_starts_none(self):
        self.assertIsNone(self.det.load_error)

    def test_not_loaded_initially(self):
        self.assertFalse(self.det._loaded)

    def test_model_is_none_initially(self):
        self.assertIsNone(self.det._model)

    def test_default_model_name(self):
        self.assertEqual(self.det.model_name, "knowledgator/gliner-pii-small-v1.0")

    def test_default_confidence(self):
        self.assertEqual(self.det.confidence, 0.85)

    def test_default_threshold(self):
        self.assertEqual(self.det.threshold, 0.5)

    def test_custom_params(self):
        det = GlinerDetector(model="my/model", confidence=0.7, threshold=0.3)
        self.assertEqual(det.model_name, "my/model")
        self.assertEqual(det.confidence, 0.7)
        self.assertEqual(det.threshold, 0.3)


@unittest.skipIf(PRESIDIO_PRESENT, "presidio установлен — нет режима 'пакет отсутствует'")
class MlDetectorMissingPackageTests(unittest.TestCase):
    """ML-детектор без presidio: detect() пуст и помечает недоступность."""

    def setUp(self):
        self.det = MlDetector()

    def test_detect_returns_empty_list(self):
        self.assertEqual(self.det.detect(CLEAN_TEXT), [])

    def test_detect_returns_list_type(self):
        self.assertIsInstance(self.det.detect(CLEAN_TEXT), list)

    def test_detect_does_not_raise(self):
        # Главное обещание плагина — отсутствие пакета не должно ронять детект.
        try:
            self.det.detect("любой текст с John Smith и Москвой")
        except Exception as exc:  # pragma: no cover
            self.fail("detect() упал при отсутствии presidio: %r" % exc)

    def test_available_false_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertFalse(self.det.available)

    def test_load_error_set_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsNotNone(self.det.load_error)

    def test_load_error_is_nonempty_string(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsInstance(self.det.load_error, str)
        self.assertTrue(len(self.det.load_error) > 0)

    def test_loaded_flag_set_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertTrue(self.det._loaded)

    def test_analyzer_stays_none(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsNone(self.det._analyzer)

    def test_detect_empty_string(self):
        self.assertEqual(self.det.detect(""), [])

    def test_detect_idempotent_returns_empty(self):
        # Повторные вызовы не должны падать и не возвращают находок.
        self.det.detect(CLEAN_TEXT)
        self.assertEqual(self.det.detect("ещё текст про Ивана Петрова"), [])

    def test_detect_idempotent_keeps_unavailable(self):
        self.det.detect(CLEAN_TEXT)
        first_error = self.det.load_error
        self.det.detect("второй вызов")
        self.assertFalse(self.det.available)
        # load_error не сбрасывается между вызовами.
        self.assertEqual(self.det.load_error, first_error)

    def test_unicode_text_safe(self):
        self.assertEqual(self.det.detect("Привет, мир! 中文 текст"), [])


@unittest.skipIf(GLINER_PRESENT, "gliner установлен — нет режима 'пакет отсутствует'")
class GlinerDetectorMissingPackageTests(unittest.TestCase):
    """GLiNER-детектор без gliner: detect() пуст и помечает недоступность."""

    def setUp(self):
        self.det = GlinerDetector()

    def test_detect_returns_empty_list(self):
        self.assertEqual(self.det.detect(CLEAN_TEXT), [])

    def test_detect_returns_list_type(self):
        self.assertIsInstance(self.det.detect(CLEAN_TEXT), list)

    def test_detect_does_not_raise(self):
        try:
            self.det.detect("John Smith works at Acme in Berlin, john@acme.com")
        except Exception as exc:  # pragma: no cover
            self.fail("detect() упал при отсутствии gliner: %r" % exc)

    def test_available_false_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertFalse(self.det.available)

    def test_load_error_set_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsNotNone(self.det.load_error)

    def test_load_error_is_nonempty_string(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsInstance(self.det.load_error, str)
        self.assertTrue(len(self.det.load_error) > 0)

    def test_loaded_flag_set_after_detect(self):
        self.det.detect(CLEAN_TEXT)
        self.assertTrue(self.det._loaded)

    def test_model_stays_none(self):
        self.det.detect(CLEAN_TEXT)
        self.assertIsNone(self.det._model)

    def test_detect_empty_string(self):
        self.assertEqual(self.det.detect(""), [])

    def test_detect_idempotent_returns_empty(self):
        self.det.detect(CLEAN_TEXT)
        self.assertEqual(self.det.detect("more text about Jane Doe"), [])

    def test_detect_idempotent_keeps_unavailable(self):
        self.det.detect(CLEAN_TEXT)
        first_error = self.det.load_error
        self.det.detect("second call")
        self.assertFalse(self.det.available)
        self.assertEqual(self.det.load_error, first_error)

    def test_unicode_text_safe(self):
        self.assertEqual(self.det.detect("Привет, мир! 中文 текст"), [])


@unittest.skipIf(PRESIDIO_PRESENT, "presidio установлен")
class MlEnabledViaConfigTests(unittest.TestCase):
    """Включение ml через Config не ломает scan()/redact() и не даёт находок."""

    def test_scan_clean_text_no_crash(self):
        cfg = Config(enabled_detectors=("ml",))
        # Не должно бросать исключений.
        scan(CLEAN_TEXT, config=cfg)

    def test_scan_clean_text_empty(self):
        cfg = Config(enabled_detectors=("ml",))
        self.assertEqual(scan(CLEAN_TEXT, config=cfg), [])

    def test_redact_clean_text_unchanged(self):
        cfg = Config(enabled_detectors=("ml",))
        result = redact(CLEAN_TEXT, config=cfg)
        self.assertEqual(result.masked_text, CLEAN_TEXT)

    def test_ml_detector_present_in_active_set(self):
        # Через enabled_detectors=("ml",) детектор попадает в активный список.
        cfg = Config(enabled_detectors=("ml",))
        engine = build_engine(cfg)
        names = {d.name for d in engine.detectors}
        self.assertIn("ml", names)

    def test_ml_not_active_by_default(self):
        # По умолчанию опциональный детектор выключен.
        engine = build_engine(Config())
        names = {d.name for d in engine.detectors}
        self.assertNotIn("ml", names)

    def test_enabling_ml_does_not_drop_core_findings(self):
        # Ядро продолжает находить email даже при включённом ml.
        cfg = Config(enabled_detectors=("ml",))
        base = {f.type for f in scan("пиши на user@example.com")}
        with_ml = {f.type for f in scan("пиши на user@example.com", config=cfg)}
        self.assertIn("EMAIL", with_ml)
        self.assertEqual(base & {"EMAIL"}, with_ml & {"EMAIL"})

    def test_enabled_via_type_person(self):
        # type == "PERSON", поэтому enabled_detectors=("PERSON",) тоже включает.
        cfg = Config(enabled_detectors=("PERSON",))
        engine = build_engine(cfg)
        names = {d.name for d in engine.detectors}
        self.assertIn("ml", names)


@unittest.skipIf(GLINER_PRESENT, "gliner установлен")
class GlinerEnabledViaConfigTests(unittest.TestCase):
    """Включение gliner через Config не ломает scan()/redact() и не даёт находок."""

    def test_scan_clean_text_no_crash(self):
        cfg = Config(enabled_detectors=("gliner",))
        scan(CLEAN_TEXT, config=cfg)

    def test_scan_clean_text_empty(self):
        cfg = Config(enabled_detectors=("gliner",))
        self.assertEqual(scan(CLEAN_TEXT, config=cfg), [])

    def test_redact_clean_text_unchanged(self):
        cfg = Config(enabled_detectors=("gliner",))
        result = redact(CLEAN_TEXT, config=cfg)
        self.assertEqual(result.masked_text, CLEAN_TEXT)

    def test_gliner_detector_present_in_active_set(self):
        cfg = Config(enabled_detectors=("gliner",))
        engine = build_engine(cfg)
        names = {d.name for d in engine.detectors}
        self.assertIn("gliner", names)

    def test_gliner_not_active_by_default(self):
        engine = build_engine(Config())
        names = {d.name for d in engine.detectors}
        self.assertNotIn("gliner", names)

    def test_enabling_gliner_does_not_drop_core_findings(self):
        cfg = Config(enabled_detectors=("gliner",))
        with_gliner = {f.type for f in scan("пиши на user@example.com", config=cfg)}
        self.assertIn("EMAIL", with_gliner)

    def test_enabled_via_type_person(self):
        cfg = Config(enabled_detectors=("PERSON",))
        engine = build_engine(cfg)
        names = {d.name for d in engine.detectors}
        self.assertIn("gliner", names)


@unittest.skipIf(PRESIDIO_PRESENT or GLINER_PRESENT, "оба пакета должны отсутствовать")
class BothPluginsEnabledTests(unittest.TestCase):
    """Одновременное включение обоих опциональных плагинов безопасно."""

    def test_scan_no_crash(self):
        cfg = Config(enabled_detectors=("ml", "gliner"))
        scan(CLEAN_TEXT, config=cfg)

    def test_clean_text_no_findings(self):
        cfg = Config(enabled_detectors=("ml", "gliner"))
        self.assertEqual(scan(CLEAN_TEXT, config=cfg), [])

    def test_redact_clean_text_unchanged(self):
        cfg = Config(enabled_detectors=("ml", "gliner"))
        self.assertEqual(redact(CLEAN_TEXT, config=cfg).masked_text, CLEAN_TEXT)

    def test_both_present_in_active_set(self):
        cfg = Config(enabled_detectors=("ml", "gliner"))
        names = {d.name for d in build_engine(cfg).detectors}
        self.assertIn("ml", names)
        self.assertIn("gliner", names)

    def test_core_still_redacts_email(self):
        # При обоих плагинах ядро продолжает маскировать email.
        cfg = Config(enabled_detectors=("ml", "gliner"))
        result = redact("contact user@example.com please", config=cfg)
        self.assertNotIn("user@example.com", result.masked_text)
        self.assertIn("[EMAIL_1]", result.masked_text)


class PluginContractTests(unittest.TestCase):
    """Контракт детекторов: интерфейс совпадает с прочими (.name/.type/.detect)."""

    def test_ml_detect_returns_findings_or_empty(self):
        # Возвращаемое — список Finding (тут пуст при отсутствии пакета).
        out = MlDetector().detect(CLEAN_TEXT)
        self.assertIsInstance(out, list)
        for item in out:
            self.assertIsInstance(item, Finding)

    def test_gliner_detect_returns_findings_or_empty(self):
        out = GlinerDetector().detect(CLEAN_TEXT)
        self.assertIsInstance(out, list)
        for item in out:
            self.assertIsInstance(item, Finding)

    def test_ml_module_exports(self):
        self.assertIn("MlDetector", ml_plugin.__all__)
        self.assertIn("build_optional", ml_plugin.__all__)

    def test_gliner_module_exports(self):
        self.assertIn("GlinerDetector", gliner_plugin.__all__)
        self.assertIn("build_optional", gliner_plugin.__all__)

    def test_names_are_distinct(self):
        self.assertNotEqual(MlDetector().name, GlinerDetector().name)


if __name__ == "__main__":
    unittest.main()
