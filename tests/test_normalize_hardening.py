"""Регресс на находки адверсариал-аудита Блока E."""
import unittest

from datashield import normalize_text


class HomoglyphPrecisionTests(unittest.TestCase):
    def test_phishing_token_still_folded(self):
        self.assertEqual(normalize_text("pаypаl", homoglyphs=True), "paypal")
        self.assertEqual(normalize_text("Gооgle", homoglyphs=True), "Google")
        # одиночная кириллица между латиницей
        self.assertEqual(normalize_text("usеr", homoglyphs=True), "user")

    def test_russian_glued_to_latin_not_corrupted(self):
        # Кириллица, окружённая кириллицей/цифрами, не сворачивается, даже если
        # в том же токене есть латиница.
        for token in ("Москва2024site", "Сбербанкonline", "Россия2024"):
            folded = normalize_text(token, homoglyphs=True)
            # русские буквы должны остаться кириллицей
            self.assertTrue(
                any("а" <= c <= "я" or "А" <= c <= "Я" for c in folded), token
            )

    def test_pure_russian_untouched(self):
        for w in ("оптимизация", "привет мир", "сообщение"):
            self.assertEqual(normalize_text(w, homoglyphs=True), w)


if __name__ == "__main__":
    unittest.main()
