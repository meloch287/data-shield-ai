"""Регресс на устойчивость plugin-API (адверсариал-аудит Блока H)."""
import unittest

from datashield.detectors.base import RegexDetector
from datashield.engine import RedactionEngine


class CrashingDetectorIsolatedTests(unittest.TestCase):
    def test_one_crashing_detector_does_not_break_scan(self):
        class Boom:
            name = "boom"
            type = "BOOM"

            def detect(self, text):
                raise RuntimeError("plugin exploded")

        email = RegexDetector("email", "EMAIL", r"\b\S+@\S+\b", 0.98)
        engine = RedactionEngine([email, Boom()])
        # падающий детектор изолирован — email всё равно найден
        found = {f.type for f in engine.analyze("email a@b.com")}
        self.assertIn("EMAIL", found)
        self.assertNotIn("BOOM", found)
        # и redact не падает
        self.assertEqual(engine.redact("a@b.com").masked_text, "[EMAIL_1]")


class GarbagePluginFilteredTests(unittest.TestCase):
    def test_non_detector_objects_are_skipped(self):
        import datashield.detectors.registry as registry

        # эмулируем плагин, который вернул мусор вместе с валидным детектором
        good = RegexDetector("emp", "EMP", r"EMP-\d{6}", 0.9)

        class FakeEP:
            def load(self):
                return lambda: [42, "garbage", good, object()]

        class FakeEPs:
            def select(self, group):
                return [FakeEP()]

        orig = registry.__dict__.get("entry_points")
        import importlib.metadata as m

        real = m.entry_points
        m.entry_points = lambda: FakeEPs()  # type: ignore[assignment]
        try:
            dets = registry._plugin_detectors()
        finally:
            m.entry_points = real  # type: ignore[assignment]
            if orig is not None:
                registry.entry_points = orig
        names = [d.name for d in dets]
        self.assertEqual(names, ["emp"])  # только валидный детектор


if __name__ == "__main__":
    unittest.main()
