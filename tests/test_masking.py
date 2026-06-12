"""Тесты аллокатора плейсхолдеров и предпросмотра."""
import unittest

from datashield.masking import PlaceholderAllocator, mask_preview


class AllocatorTests(unittest.TestCase):
    def test_numbering_per_type(self):
        alloc = PlaceholderAllocator()
        self.assertEqual(alloc.placeholder_for("EMAIL", "a@b.com"), "[EMAIL_1]")
        self.assertEqual(alloc.placeholder_for("EMAIL", "c@d.com"), "[EMAIL_2]")
        self.assertEqual(alloc.placeholder_for("PHONE", "123"), "[PHONE_1]")

    def test_same_value_stable(self):
        alloc = PlaceholderAllocator()
        first = alloc.placeholder_for("EMAIL", "a@b.com")
        second = alloc.placeholder_for("EMAIL", "a@b.com")
        self.assertEqual(first, second)

    def test_custom_template(self):
        alloc = PlaceholderAllocator("<<{type}:{n}>>")
        self.assertEqual(alloc.placeholder_for("CARD", "x"), "<<CARD:1>>")

    def test_mapping_has_no_raw_values(self):
        alloc = PlaceholderAllocator()
        alloc.placeholder_for("EMAIL", "secret@b.com")
        self.assertEqual(alloc.mapping, {"[EMAIL_1]": "EMAIL"})
        self.assertNotIn("secret@b.com", str(alloc.mapping))


class PreviewTests(unittest.TestCase):
    def test_preview_hides_value(self):
        self.assertEqual(mask_preview("john"), "j***")

    def test_short_value(self):
        self.assertEqual(mask_preview("a"), "*")

    def test_empty(self):
        self.assertEqual(mask_preview(""), "")


if __name__ == "__main__":
    unittest.main()
