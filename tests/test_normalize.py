"""Юнит-тесты модуля datashield.normalize.

Покрывает:
- nfkc: полноширинные цифры/буквы, совместимые формы (лигатуры, ㎏, римские),
  идемпотентность, пустую строку.
- fold_homoglyphs: сворачивание спутываемых символов ТОЛЬКО в смешанных по
  алфавиту токенах, сохранность чисто кириллических и чисто латинских слов,
  сохранность разделителей/пробелов, идемпотентность, покрытие карты пар.
- normalize_text: режимы homoglyphs True/False, keyword-only флаг, пустая строка.
- публичный реэкспорт from datashield import normalize_text.
"""
import unicodedata
import unittest

from datashield import normalize_text as public_normalize_text
from datashield.normalize import (
    _CONFUSABLES,
    fold_homoglyphs,
    nfkc,
    normalize_text,
)


class NfkcTests(unittest.TestCase):
    def test_fullwidth_digits(self):
        # Полноширинные цифры (как в обфусцированном номере карты) → ASCII.
        self.assertEqual(nfkc("４１１１"), "4111")

    def test_fullwidth_card_with_spaces(self):
        self.assertEqual(
            nfkc("４１１１ １１１１ １１１１ １１１１"),
            "4111 1111 1111 1111",
        )

    def test_fullwidth_letters(self):
        self.assertEqual(nfkc("ＡＢＣ"), "ABC")
        self.assertEqual(nfkc("ｈｅｌｌｏ"), "hello")

    def test_ligature_fi(self):
        # Лигатура ﬁ раскладывается в две буквы.
        self.assertEqual(nfkc("ﬁle"), "file")

    def test_ligature_ff(self):
        self.assertEqual(nfkc("ﬀ"), "ff")

    def test_squared_kg(self):
        # Символ ㎏ (U+338F) — совместимая форма «kg».
        self.assertEqual(nfkc("㎏"), "kg")

    def test_roman_numeral_compat(self):
        # Совместимая римская цифра Ⅻ → "XII".
        self.assertEqual(nfkc("Ⅻ"), "XII")

    def test_plain_ascii_unchanged(self):
        self.assertEqual(nfkc("paypal hello 123"), "paypal hello 123")

    def test_cyrillic_unchanged(self):
        # Обычный русский текст NFKC не трогает.
        self.assertEqual(nfkc("оптимизация привет"), "оптимизация привет")

    def test_empty_string(self):
        self.assertEqual(nfkc(""), "")

    def test_idempotent(self):
        for sample in ["４１１１", "ﬁle", "㎏", "ＡＢＣ", "Ⅻ", "оптимизация"]:
            once = nfkc(sample)
            self.assertEqual(nfkc(once), once, f"не идемпотентно для {sample!r}")

    def test_matches_stdlib_nfkc(self):
        # nfkc — тонкая обёртка над unicodedata.normalize("NFKC", ...).
        sample = "４Ａﬁ㎏Ⅻ"
        self.assertEqual(nfkc(sample), unicodedata.normalize("NFKC", sample))


class FoldHomoglyphsMixedScriptTests(unittest.TestCase):
    def test_paypal_with_cyrillic_a_folds(self):
        # "pаypаl" — латиница p,y,p,l + кириллические а → чистая латиница.
        mixed = "pаypаl"  # а = U+0430 CYRILLIC SMALL A
        self.assertEqual(fold_homoglyphs(mixed), "paypal")

    def test_google_with_cyrillic_o_folds(self):
        # "Gооgle" с кириллическими о.
        mixed = "Gооgle"  # о = U+043E CYRILLIC SMALL O
        self.assertEqual(fold_homoglyphs(mixed), "Google")

    def test_mixed_token_with_punctuation_folds_whole_token(self):
        # Точка не является разделителем токена → весь "pаypаl.com" сворачивается.
        mixed = "pаypаl.com"
        self.assertEqual(fold_homoglyphs(mixed), "paypal.com")

    def test_mixed_email_token_folds(self):
        # usеr@gmail.com — кириллическая е, есть латиница → сворачивается целиком.
        mixed = "usеr@gmail.com"
        self.assertEqual(fold_homoglyphs(mixed), "user@gmail.com")

    def test_greek_homoglyphs_in_mixed_token(self):
        # Греческая ο (U+03BF) рядом с латиницей.
        mixed = "gοοgle"
        self.assertEqual(fold_homoglyphs(mixed), "google")


class FoldHomoglyphsPureScriptTests(unittest.TestCase):
    def test_pure_cyrillic_word_unchanged(self):
        # Нет латиницы → ничего не сворачиваем, слово остаётся кириллицей.
        word = "оптимизация"
        self.assertEqual(fold_homoglyphs(word), word)

    def test_pure_cyrillic_privet_unchanged(self):
        word = "привет"
        self.assertEqual(fold_homoglyphs(word), word)

    def test_pure_cyrillic_phrase_with_punctuation_unchanged(self):
        phrase = "привет, мир"
        self.assertEqual(fold_homoglyphs(phrase), phrase)

    def test_pure_latin_paypal_unchanged(self):
        # Нет спутываемых символов → токен возвращается как есть.
        self.assertEqual(fold_homoglyphs("paypal"), "paypal")

    def test_pure_latin_hello_unchanged(self):
        self.assertEqual(fold_homoglyphs("hello"), "hello")

    def test_digits_and_symbols_unchanged(self):
        self.assertEqual(fold_homoglyphs("4111 1111"), "4111 1111")


class FoldHomoglyphsSeparatorTests(unittest.TestCase):
    def test_spaces_preserved_and_words_handled_independently(self):
        mixed = "pаypаl hello"
        self.assertEqual(fold_homoglyphs(mixed), "paypal hello")

    def test_double_space_preserved(self):
        mixed = "pаypаl  hello"
        self.assertEqual(fold_homoglyphs(mixed), "paypal  hello")

    def test_tab_and_newline_preserved(self):
        mixed = "pаypаl\thello\nworld"
        self.assertEqual(fold_homoglyphs(mixed), "paypal\thello\nworld")

    def test_pure_cyrillic_neighbor_untouched(self):
        # Смешанный токен сворачивается, чисто кириллический сосед остаётся.
        mixed = "pаypаl\n\nоптимизация"
        self.assertEqual(fold_homoglyphs(mixed), "paypal\n\nоптимизация")

    def test_empty_string(self):
        self.assertEqual(fold_homoglyphs(""), "")

    def test_idempotent(self):
        mixed = "pаypаl оптимизация hello"
        once = fold_homoglyphs(mixed)
        self.assertEqual(fold_homoglyphs(once), once)
        self.assertEqual(once, "paypal оптимизация hello")


class ConfusableMapCoverageTests(unittest.TestCase):
    def test_representative_lowercase_pairs(self):
        # Несколько представительных пар из карты спутываемых символов.
        expected = {
            "а": "a",  # а
            "е": "e",  # е
            "о": "o",  # о
            "р": "p",  # р
            "с": "c",  # с
            "у": "y",  # у
            "х": "x",  # х
            "к": "k",  # к
            "ο": "o",  # греческая ο
            "α": "a",  # греческая α
        }
        for cyr, lat in expected.items():
            self.assertEqual(
                _CONFUSABLES.get(cyr),
                lat,
                f"карта спутываемых: {cyr!r} ожидалось → {lat!r}",
            )

    def test_uppercase_pair_present(self):
        self.assertEqual(_CONFUSABLES.get("А"), "A")  # А → A

    def test_map_values_are_ascii_latin(self):
        # Все целевые значения карты — печатные ASCII-латинские символы.
        for src, dst in _CONFUSABLES.items():
            self.assertEqual(len(dst), 1, f"замена для {src!r} должна быть 1 символ")
            self.assertTrue(dst.isascii() and dst.isalpha(), f"{dst!r} не ASCII-буква")

    def test_map_keys_are_non_latin(self):
        # Ключи карты — не латиница (иначе сворачивать нечего).
        latin = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        for src in _CONFUSABLES:
            self.assertNotIn(src, latin, f"ключ {src!r} не должен быть латиницей")

    def test_every_pair_folds_in_mixed_token(self):
        # Каждый символ карты сворачивается, будучи дополнен латинской буквой.
        for src, dst in _CONFUSABLES.items():
            token = src + "x"  # гарантированно смешанный токен (x — латиница)
            self.assertEqual(fold_homoglyphs(token), dst + "x")


class NormalizeTextTests(unittest.TestCase):
    def test_default_does_not_fold_homoglyphs(self):
        # По умолчанию homoglyphs=False: NFKC применяется, гомоглифы остаются.
        mixed = "pаypаl"
        self.assertEqual(normalize_text(mixed), mixed)

    def test_homoglyphs_true_folds(self):
        mixed = "pаypаl"
        self.assertEqual(normalize_text(mixed, homoglyphs=True), "paypal")

    def test_nfkc_applied_by_default(self):
        # Полноширинные цифры нормализуются даже без homoglyphs.
        self.assertEqual(normalize_text("４１１１"), "4111")

    def test_nfkc_and_homoglyphs_combined(self):
        # NFKC сначала, затем сворачивание гомоглифов.
        mixed = "４１１１ pаypаl"
        self.assertEqual(normalize_text(mixed, homoglyphs=True), "4111 paypal")

    def test_pure_cyrillic_unchanged_in_both_modes(self):
        word = "оптимизация"
        self.assertEqual(normalize_text(word), word)
        self.assertEqual(normalize_text(word, homoglyphs=True), word)

    def test_empty_string(self):
        self.assertEqual(normalize_text(""), "")
        self.assertEqual(normalize_text("", homoglyphs=True), "")

    def test_homoglyphs_is_keyword_only(self):
        # Сигнатура: normalize_text(text, *, homoglyphs=False).
        with self.assertRaises(TypeError):
            normalize_text("pаypаl", True)  # noqa: позиционный запрещён

    def test_public_export_is_same_callable(self):
        self.assertIs(public_normalize_text, normalize_text)


if __name__ == "__main__":
    unittest.main()
