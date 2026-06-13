"""Тесты для datashield.formats — детерминированные format-preserving фейки.

Проверяем РЕАЛЬНОЕ поведение модуля (см. datashield/formats.py):
  - byte_stream: детерминизм, диапазон 0..255, зависимость от seed;
  - map_digits: сохранение длины и разделителей, первая цифра != 0, детерминизм;
  - fake_card: валидность по Луну (validators.luhn_check) и сохранение длины;
  - fake_email / fake_phone / fake_person: форма и детерминизм;
  - fake_for_type: диспетчеризация по типу и fallback для неизвестных типов.

Только stdlib unittest, без сторонних зависимостей.
"""
from __future__ import annotations

import itertools
import unittest

from datashield.data.names import EN_GIVEN_NAMES, RU_GIVEN_NAMES
from datashield.formats import (
    byte_stream,
    fake_card,
    fake_email,
    fake_for_type,
    fake_person,
    fake_phone,
    map_digits,
)
from datashield.validators import luhn_check


def _separators(s: str) -> list:
    """Список несифровых символов в порядке появления (структура строки)."""
    return [c for c in s if not c.isdigit()]


class ByteStreamTests(unittest.TestCase):
    def test_yields_bytes_in_range(self):
        gen = byte_stream("seed-x")
        sample = list(itertools.islice(gen, 100))
        self.assertEqual(len(sample), 100)
        self.assertTrue(all(isinstance(b, int) for b in sample))
        self.assertTrue(all(0 <= b <= 255 for b in sample))

    def test_deterministic_same_seed(self):
        a = list(itertools.islice(byte_stream("same"), 64))
        b = list(itertools.islice(byte_stream("same"), 64))
        self.assertEqual(a, b)

    def test_different_seed_differs(self):
        a = list(itertools.islice(byte_stream("seed-a"), 64))
        b = list(itertools.islice(byte_stream("seed-b"), 64))
        self.assertNotEqual(a, b)

    def test_is_effectively_infinite(self):
        # Поток должен спокойно выдавать более одного 32-байтного блока sha256.
        gen = byte_stream("long")
        sample = list(itertools.islice(gen, 1000))
        self.assertEqual(len(sample), 1000)

    def test_crosses_block_boundary_consistently(self):
        # Значения за пределами первого блока (32 байта) тоже детерминированы.
        a = list(itertools.islice(byte_stream("blk"), 200))
        b = list(itertools.islice(byte_stream("blk"), 200))
        self.assertEqual(a[32:], b[32:])


class MapDigitsTests(unittest.TestCase):
    def test_preserves_length(self):
        orig = "4111-1111-1111-1111"
        out = map_digits(orig, "k1")
        self.assertEqual(len(out), len(orig))

    def test_preserves_separators_positions(self):
        orig = "+7 (912) 345-67-89"
        out = map_digits(orig, "k1")
        self.assertEqual(_separators(out), _separators(orig))
        # И сами разделители на тех же индексах.
        for i, ch in enumerate(orig):
            if not ch.isdigit():
                self.assertEqual(out[i], ch)

    def test_only_digits_change(self):
        orig = "ID-2024-XY"
        out = map_digits(orig, "k1")
        for i, ch in enumerate(orig):
            if ch.isdigit():
                self.assertTrue(out[i].isdigit())
            else:
                self.assertEqual(out[i], ch)

    def test_first_digit_not_zero(self):
        # Даже если исходные цифры все нули, первая цифра результата != "0".
        out = map_digits("000000", "anything")
        first_digit = next(c for c in out if c.isdigit())
        self.assertNotEqual(first_digit, "0")

    def test_first_digit_not_zero_across_many_seeds(self):
        for i in range(200):
            out = map_digits("000000", f"seed{i}")
            first_digit = next(c for c in out if c.isdigit())
            self.assertNotEqual(first_digit, "0", f"seed{i} -> {out!r}")

    def test_first_digit_after_leading_separators(self):
        # "Первая цифра" — это первая цифровая позиция, даже после нецифр.
        out = map_digits("+++5", "s")
        self.assertNotEqual(out[-1], "0")
        self.assertEqual(out[:3], "+++")

    def test_deterministic_same_seed(self):
        orig = "4111-1111-1111-1111"
        self.assertEqual(map_digits(orig, "k1"), map_digits(orig, "k1"))

    def test_different_seed_differs(self):
        orig = "4111-1111-1111-1111"
        self.assertNotEqual(map_digits(orig, "k1"), map_digits(orig, "k2"))

    def test_no_digits_returns_original(self):
        self.assertEqual(map_digits("---no---", "k"), "---no---")
        self.assertEqual(map_digits("", "k"), "")
        self.assertEqual(map_digits("abc def", "k"), "abc def")

    def test_single_digit_forced_nonzero(self):
        # Одна цифра: первая цифра не должна стать "0".
        out = map_digits("a0b", "s")
        self.assertEqual(out[0], "a")
        self.assertEqual(out[2], "b")
        self.assertNotEqual(out[1], "0")
        self.assertTrue(out[1].isdigit())

    def test_later_digits_may_be_zero(self):
        # Инвариант "не ноль" — только для ПЕРВОЙ цифры; остальные могут быть 0.
        found_zero = any(
            "0" in map_digits("11111111", f"seed{i}")[1:] for i in range(60)
        )
        self.assertTrue(found_zero)

    def test_luhn_flag_makes_valid_and_keeps_length(self):
        orig = "4111111111111111"
        out = map_digits(orig, "k", luhn=True)
        self.assertEqual(len(out), len(orig))
        self.assertTrue(luhn_check(out))

    def test_luhn_flag_ignored_for_single_digit(self):
        # luhn применяется только при len(new_digits) >= 2; одна цифра — без него.
        out = map_digits("5", "s", luhn=True)
        self.assertEqual(len(out), 1)
        self.assertTrue(out.isdigit())


class FakeCardTests(unittest.TestCase):
    def test_luhn_valid_various_seeds(self):
        for seed in ("a", "b", "c", "seed42", "xyz", "длинный-ключ"):
            out = fake_card("4111111111111111", seed)
            self.assertTrue(luhn_check(out), f"seed={seed} -> {out}")

    def test_length_preserved_plain(self):
        orig = "4111111111111111"
        out = fake_card(orig, "s")
        self.assertEqual(len(out), len(orig))

    def test_length_and_separators_preserved(self):
        orig = "4111 1111 1111 1111"
        out = fake_card(orig, "sep")
        self.assertEqual(len(out), len(orig))
        self.assertEqual(_separators(out), _separators(orig))
        self.assertTrue(luhn_check(out))

    def test_first_digit_not_zero(self):
        out = fake_card("4111111111111111", "zz")
        self.assertNotEqual(out[0], "0")

    def test_deterministic(self):
        self.assertEqual(
            fake_card("4111111111111111", "k"),
            fake_card("4111111111111111", "k"),
        )

    def test_different_seed_differs(self):
        self.assertNotEqual(
            fake_card("4111111111111111", "k1"),
            fake_card("4111111111111111", "k2"),
        )

    def test_15_digit_amex_length_luhn(self):
        orig = "3782 822463 10005"
        out = fake_card(orig, "amex")
        self.assertEqual(len(out), len(orig))
        self.assertEqual(_separators(out), _separators(orig))
        self.assertTrue(luhn_check(out))


class FakeEmailTests(unittest.TestCase):
    def test_shape(self):
        out = fake_email("mail-seed")
        self.assertTrue(out.startswith("user"))
        self.assertTrue(out.endswith("@example.invalid"))
        local = out.split("@", 1)[0]
        digits = local[len("user"):]
        self.assertEqual(len(digits), 6)
        self.assertTrue(digits.isdigit())

    def test_deterministic(self):
        self.assertEqual(fake_email("seed-1"), fake_email("seed-1"))

    def test_different_seed_differs(self):
        self.assertNotEqual(fake_email("seed-1"), fake_email("seed-2"))

    def test_uses_reserved_invalid_tld(self):
        # .invalid — зарезервированный TLD (RFC 2606): фейк гарантированно не доставится.
        self.assertIn("@example.invalid", fake_email("x"))


class FakePhoneTests(unittest.TestCase):
    def test_length_and_separators_preserved(self):
        orig = "+7 (912) 345-67-89"
        out = fake_phone(orig, "p1")
        self.assertEqual(len(out), len(orig))
        self.assertEqual(_separators(out), _separators(orig))

    def test_only_digits_change(self):
        orig = "+1-202-555-0173"
        out = fake_phone(orig, "p")
        for i, ch in enumerate(orig):
            if not ch.isdigit():
                self.assertEqual(out[i], ch)

    def test_deterministic(self):
        orig = "+7 912 345 67 89"
        self.assertEqual(fake_phone(orig, "p"), fake_phone(orig, "p"))

    def test_different_seed_differs(self):
        orig = "+7 912 345 67 89"
        self.assertNotEqual(fake_phone(orig, "a"), fake_phone(orig, "b"))

    def test_matches_map_digits(self):
        # fake_phone — это map_digits без luhn.
        orig = "8 800 555 35 35"
        self.assertEqual(fake_phone(orig, "s"), map_digits(orig, "s"))


class FakePersonTests(unittest.TestCase):
    def test_en_input_uses_en_pool(self):
        out = fake_person("John Smith", "s1")
        words = out.split()
        self.assertEqual(len(words), 2)
        for w in words:
            self.assertIn(w.lower(), EN_GIVEN_NAMES, w)

    def test_ru_input_uses_ru_pool(self):
        out = fake_person("Иван Петров", "s2")
        words = out.split()
        self.assertEqual(len(words), 2)
        for w in words:
            self.assertIn(w.lower(), RU_GIVEN_NAMES, w)

    def test_word_count_preserved(self):
        self.assertEqual(len(fake_person("Bob", "x").split()), 1)
        self.assertEqual(len(fake_person("Anna Maria Lee", "x").split()), 3)

    def test_title_cased(self):
        out = fake_person("John Smith", "tc")
        for w in out.split():
            self.assertEqual(w, w.title())

    def test_deterministic(self):
        self.assertEqual(fake_person("John Smith", "s"), fake_person("John Smith", "s"))

    def test_different_seed_differs(self):
        self.assertNotEqual(
            fake_person("John Smith", "s1"),
            fake_person("John Smith", "s9"),
        )

    def test_empty_input_yields_one_word(self):
        # original[:1] == "" -> не ascii-alpha -> RU-пул; max(1, 0) == 1 слово.
        out = fake_person("", "s")
        words = out.split()
        self.assertEqual(len(words), 1)
        self.assertIn(words[0].lower(), RU_GIVEN_NAMES)


class FakeForTypeTests(unittest.TestCase):
    def test_credit_card_dispatch(self):
        out = fake_for_type("CREDIT_CARD", "4111111111111111", "s")
        self.assertEqual(out, fake_card("4111111111111111", "s"))
        self.assertTrue(luhn_check(out))

    def test_email_dispatch(self):
        out = fake_for_type("EMAIL", "alice@example.com", "s")
        self.assertEqual(out, fake_email("s"))

    def test_phone_dispatch(self):
        out = fake_for_type("PHONE", "+7 912 000", "s")
        self.assertEqual(out, fake_phone("+7 912 000", "s"))

    def test_phone_ru_dispatch(self):
        out = fake_for_type("PHONE_RU", "+7 912 000", "s")
        self.assertEqual(out, fake_phone("+7 912 000", "s"))

    def test_person_dispatch(self):
        out = fake_for_type("PERSON", "John Smith", "s")
        self.assertEqual(out, fake_person("John Smith", "s"))

    def test_unknown_type_with_digits_uses_map_digits(self):
        out = fake_for_type("SOMEID", "ID-2024-99", "s")
        self.assertEqual(out, map_digits("ID-2024-99", "s"))
        # Длина и разделители сохранены через map_digits.
        self.assertEqual(len(out), len("ID-2024-99"))
        self.assertEqual(_separators(out), _separators("ID-2024-99"))

    def test_unknown_nondigit_fallback_shape(self):
        out = fake_for_type("WEIRD", "hello", "s")
        self.assertTrue(out.startswith("weird"))
        trailing = out[len("weird"):]
        self.assertEqual(len(trailing), 4)
        self.assertTrue(trailing.isdigit())

    def test_unknown_nondigit_fallback_deterministic(self):
        self.assertEqual(
            fake_for_type("WEIRD", "hello", "s"),
            fake_for_type("WEIRD", "hello", "s"),
        )

    def test_unknown_nondigit_fallback_seed_sensitive(self):
        self.assertNotEqual(
            fake_for_type("WEIRD", "hello", "s1"),
            fake_for_type("WEIRD", "hello", "s2"),
        )

    def test_unknown_nondigit_fallback_ignores_value_content(self):
        # Для нецифрового нераспознанного типа значение игнорируется (только seed+тип).
        self.assertEqual(
            fake_for_type("WEIRD", "hello", "s"),
            fake_for_type("WEIRD", "goodbye", "s"),
        )

    def test_unknown_type_lowercased_in_fallback(self):
        out = fake_for_type("CustomTag", "abc", "s")
        self.assertTrue(out.startswith("customtag"))


if __name__ == "__main__":
    unittest.main()
