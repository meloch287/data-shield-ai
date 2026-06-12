"""Тесты движка: пересечения, стабильные плейсхолдеры, allowlist, порог."""
import unittest

from datashield import Config, redact, scan
from datashield.detectors.base import Finding
from datashield.engine import resolve_overlaps


class PlaceholderStabilityTests(unittest.TestCase):
    def test_same_value_same_placeholder(self):
        result = redact("пиши на a@b.com или снова a@b.com")
        self.assertEqual(result.masked_text.count("[EMAIL_1]"), 2)
        self.assertNotIn("[EMAIL_2]", result.masked_text)

    def test_different_values_increment(self):
        result = redact("a@b.com и c@d.com")
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[EMAIL_2]", result.masked_text)


class OverlapTests(unittest.TestCase):
    def test_ru_phone_wins_over_intl(self):
        findings = scan("звони +7 909 123 45 67 утром")
        phone_findings = [f for f in findings if f.type.startswith("PHONE")]
        self.assertEqual(len(phone_findings), 1)
        self.assertEqual(phone_findings[0].type, "PHONE_RU")

    def test_resolve_overlaps_prefers_confidence(self):
        a = Finding("PHONE_RU", 0, 10, "x", 0.85, "ru")
        b = Finding("PHONE", 0, 10, "x", 0.8, "intl")
        resolved = resolve_overlaps([b, a])
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].type, "PHONE_RU")

    def test_non_overlapping_both_kept(self):
        a = Finding("EMAIL", 0, 5, "x", 0.9, "e")
        b = Finding("IP", 10, 15, "y", 0.9, "i")
        self.assertEqual(len(resolve_overlaps([a, b])), 2)


class ThresholdTests(unittest.TestCase):
    def test_min_confidence_filters(self):
        # ИНН без контекста — 0.55; поднимаем порог не нужно, он и так выше.
        self.assertEqual(scan("число 7707083893 тут"), [])

    def test_lower_threshold_catches_more(self):
        found = {f.type for f in scan("число 7707083893 тут", min_confidence=0.5)}
        self.assertIn("INN", found)


class AllowlistTests(unittest.TestCase):
    def test_allowlisted_domain_skipped(self):
        cfg = Config(allowlist=("example.com",))
        result = redact("письмо на john@example.com сегодня", config=cfg)
        self.assertIn("john@example.com", result.masked_text)

    def test_non_allowlisted_still_masked(self):
        cfg = Config(allowlist=("example.com",))
        result = redact("письмо на john@other.org сегодня", config=cfg)
        self.assertNotIn("john@other.org", result.masked_text)


class FilterTests(unittest.TestCase):
    def test_only_filter(self):
        found = {f.type for f in scan("a@b.com и 192.168.0.1", only=["EMAIL"])}
        self.assertEqual(found, {"EMAIL"})

    def test_exclude_filter(self):
        found = {f.type for f in scan("a@b.com и 192.168.0.1", exclude=["EMAIL"])}
        self.assertNotIn("EMAIL", found)
        self.assertIn("IP", found)


class EmptyInputTests(unittest.TestCase):
    def test_empty(self):
        result = redact("")
        self.assertEqual(result.masked_text, "")
        self.assertEqual(result.stats, {})


if __name__ == "__main__":
    unittest.main()
