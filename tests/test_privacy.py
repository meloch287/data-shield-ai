"""Тест приватности: сырые оригиналы не утекают в отчёт аудита."""
import json
import unittest

from datashield import redact


class ReportPrivacyTests(unittest.TestCase):
    def test_report_contains_no_raw_values(self):
        email = "verysecret.person@private.example"
        card = "4111111111111111"
        result = redact(f"почта {email}, карта {card}")
        report = result.report()
        dumped = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(email, dumped)
        self.assertNotIn(card, dumped)

    def test_report_has_hashes_and_meta(self):
        result = redact("почта a@b.com")
        report = result.report()
        self.assertEqual(report["total"], 1)
        entry = report["entries"][0]
        self.assertEqual(entry["type"], "EMAIL")
        self.assertIn("value_sha256", entry)
        self.assertIn("salt", report)

    def test_salt_changes_hash(self):
        result = redact("почта a@b.com")
        h1 = result.report(salt=b"AAAA")["entries"][0]["value_sha256"]
        h2 = result.report(salt=b"BBBB")["entries"][0]["value_sha256"]
        self.assertNotEqual(h1, h2)

    def test_placeholders_map_has_no_raw_values(self):
        result = redact("почта a@b.com")
        self.assertNotIn("a@b.com", str(result.placeholders))


if __name__ == "__main__":
    unittest.main()
