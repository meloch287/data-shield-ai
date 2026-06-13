"""Тесты стратегий замены (Block B).

Покрывает datashield.strategies (5 стратегий + фабрика + partial_mask),
datashield.formats (детерминированные фейки), datashield.masking.ReplacementContext
и интеграцию через redact(strategy=...) + restore.

Только stdlib unittest, без сторонних зависимостей. Утверждается РЕАЛЬНОЕ
поведение, проверенное на исходниках.
"""
import re
import unittest

from datashield import Config, redact, restore, scan
from datashield.detectors.base import Finding
from datashield.formats import (
    byte_stream,
    fake_card,
    fake_email,
    fake_for_type,
    fake_person,
    fake_phone,
    map_digits,
)
from datashield.masking import ReplacementContext
from datashield.strategies import (
    STRATEGIES,
    HashStrategy,
    PartialStrategy,
    PlaceholderStrategy,
    PseudonymStrategy,
    RemoveStrategy,
    make_strategy,
    partial_mask,
)
from datashield.validators import luhn_check


def _f(type_name, value, n_start=0):
    """Удобный конструктор Finding для тестов."""
    return Finding(type_name, n_start, n_start + len(value), value, 0.9, "test")


# ---------------------------------------------------------------------------
# partial_mask — краевые случаи
# ---------------------------------------------------------------------------
class PartialMaskTests(unittest.TestCase):
    def test_keeps_last_n_alnum_masks_rest_preserving_separators(self):
        # Разделители (пробелы) сохраняются, последние 4 буквенно-цифровых видны.
        self.assertEqual(
            partial_mask("4111 1111 1111 1234"), "**** **** **** 1234"
        )

    def test_default_visible_is_four(self):
        self.assertEqual(partial_mask("abcdef1234"), "******1234")

    def test_visible_zero_masks_all_alnum(self):
        self.assertEqual(partial_mask("abcd1234", 0), "********")

    def test_visible_greater_than_length_keeps_everything(self):
        self.assertEqual(partial_mask("ab12", 10), "ab12")

    def test_visible_equal_to_alnum_count(self):
        self.assertEqual(partial_mask("ab12", 4), "ab12")

    def test_negative_visible_masks_everything(self):
        # visible > 0 ложно -> keep=set() -> всё буквенно-цифровое маскируется.
        self.assertEqual(partial_mask("abcdef", -2), "******")

    def test_custom_mask_char(self):
        self.assertEqual(partial_mask("hello world", 2, "X"), "XXXXX XXXld")

    def test_empty_string(self):
        self.assertEqual(partial_mask(""), "")

    def test_all_separators_unchanged(self):
        self.assertEqual(partial_mask("---...///"), "---...///")

    def test_separators_in_middle_preserved(self):
        # Точка и @ — не alnum, остаются; последние 4 alnum: 'e','c','o','m'.
        self.assertEqual(partial_mask("john@example.com"), "****@******e.com")

    def test_length_is_preserved(self):
        for value in ("abc", "1234-5678", "a b c d e", "X.Y.Z"):
            self.assertEqual(len(partial_mask(value, 2)), len(value))

    def test_unicode_alnum_counts(self):
        # Кириллица — буквенно-цифровая, так что маскируется как обычные буквы.
        masked = partial_mask("привет", 2)
        self.assertEqual(len(masked), len("привет"))
        self.assertTrue(masked.endswith("ет"))
        self.assertTrue(masked.startswith("*"))


# ---------------------------------------------------------------------------
# PlaceholderStrategy
# ---------------------------------------------------------------------------
class PlaceholderStrategyTests(unittest.TestCase):
    def test_default_template_format(self):
        s = PlaceholderStrategy()
        self.assertEqual(s.generate(_f("EMAIL", "a@b.com"), 1), "[EMAIL_1]")
        self.assertEqual(s.generate(_f("CREDIT_CARD", "x"), 3), "[CREDIT_CARD_3]")

    def test_custom_template(self):
        s = PlaceholderStrategy("<<{type}:{n}>>")
        self.assertEqual(s.generate(_f("CARD", "x"), 7), "<<CARD:7>>")

    def test_is_reversible(self):
        self.assertTrue(PlaceholderStrategy.reversible)
        self.assertTrue(PlaceholderStrategy().reversible)

    def test_uses_finding_type_not_value(self):
        out = PlaceholderStrategy().generate(_f("PHONE", "secret-number"), 2)
        self.assertEqual(out, "[PHONE_2]")
        self.assertNotIn("secret-number", out)


# ---------------------------------------------------------------------------
# PseudonymStrategy — fake-but-plausible, детерминизм
# ---------------------------------------------------------------------------
class PseudonymStrategyTests(unittest.TestCase):
    def test_is_reversible(self):
        self.assertTrue(PseudonymStrategy.reversible)

    def test_email_is_plausible_and_invalid_domain(self):
        out = PseudonymStrategy().generate(_f("EMAIL", "john@real.com"), 1)
        self.assertTrue(out.endswith("@example.invalid"))
        self.assertTrue(out.startswith("user"))
        self.assertNotIn("john", out)
        self.assertNotIn("real.com", out)

    def test_card_is_luhn_valid_and_form_preserving(self):
        original = "4111 1111 1111 1111"
        out = PseudonymStrategy().generate(_f("CREDIT_CARD", original), 1)
        self.assertEqual(len(out), len(original))
        # Разделители (пробелы) на тех же позициях.
        self.assertEqual(
            [i for i, c in enumerate(out) if c == " "],
            [i for i, c in enumerate(original) if c == " "],
        )
        self.assertTrue(luhn_check(out.replace(" ", "")))
        self.assertNotEqual(out, original)

    def test_phone_preserves_separators_and_length(self):
        original = "+7 916 123-45-67"
        out = PseudonymStrategy().generate(_f("PHONE", original), 1)
        self.assertEqual(len(out), len(original))
        for i, c in enumerate(original):
            if not c.isdigit():
                self.assertEqual(out[i], c)

    def test_person_preserves_word_count(self):
        out = PseudonymStrategy().generate(_f("PERSON", "John Smith"), 1)
        self.assertEqual(len(out.split()), 2)

    def test_deterministic_same_key_same_value(self):
        a = PseudonymStrategy("k").generate(_f("EMAIL", "x@y.com"), 1)
        b = PseudonymStrategy("k").generate(_f("EMAIL", "x@y.com"), 99)
        self.assertEqual(a, b)  # n не влияет на псевдоним

    def test_different_key_yields_different_pseudonym(self):
        a = PseudonymStrategy("key-a").generate(_f("CREDIT_CARD", "4111111111111111"), 1)
        b = PseudonymStrategy("key-b").generate(_f("CREDIT_CARD", "4111111111111111"), 1)
        self.assertNotEqual(a, b)

    def test_different_value_yields_different_pseudonym(self):
        s = PseudonymStrategy()
        a = s.generate(_f("EMAIL", "a@b.com"), 1)
        b = s.generate(_f("EMAIL", "c@d.com"), 1)
        self.assertNotEqual(a, b)


# ---------------------------------------------------------------------------
# PartialStrategy
# ---------------------------------------------------------------------------
class PartialStrategyTests(unittest.TestCase):
    def test_is_not_reversible(self):
        self.assertFalse(PartialStrategy.reversible)

    def test_default_keeps_last_four(self):
        out = PartialStrategy().generate(_f("CREDIT_CARD", "4111 1111 1111 1111"), 1)
        self.assertEqual(out, "**** **** **** 1111")

    def test_custom_visible_and_mask_char(self):
        out = PartialStrategy(visible=2, mask_char="#").generate(_f("X", "abcdef"), 1)
        self.assertEqual(out, "####ef")

    def test_ignores_numbering(self):
        s = PartialStrategy()
        a = s.generate(_f("X", "abcd1234"), 1)
        b = s.generate(_f("X", "abcd1234"), 42)
        self.assertEqual(a, b)


# ---------------------------------------------------------------------------
# HashStrategy — [TYPE_<10hex>], стабильно на значение
# ---------------------------------------------------------------------------
class HashStrategyTests(unittest.TestCase):
    HEX10 = re.compile(r"^\[(?P<type>[A-Z_]+)_(?P<hex>[0-9a-f]{10})\]$")

    def test_is_reversible(self):
        self.assertTrue(HashStrategy.reversible)

    def test_format_is_type_underscore_10hex(self):
        out = HashStrategy().generate(_f("EMAIL", "john@x.com"), 1)
        m = self.HEX10.match(out)
        self.assertIsNotNone(m, out)
        self.assertEqual(m.group("type"), "EMAIL")
        self.assertEqual(len(m.group("hex")), 10)

    def test_stable_per_value_ignores_n(self):
        s = HashStrategy()
        a = s.generate(_f("EMAIL", "john@x.com"), 1)
        b = s.generate(_f("EMAIL", "john@x.com"), 7)
        self.assertEqual(a, b)

    def test_different_values_differ(self):
        s = HashStrategy()
        a = s.generate(_f("EMAIL", "a@b.com"), 1)
        b = s.generate(_f("EMAIL", "c@d.com"), 1)
        self.assertNotEqual(a, b)

    def test_key_changes_digest(self):
        a = HashStrategy("k1").generate(_f("EMAIL", "a@b.com"), 1)
        b = HashStrategy("k2").generate(_f("EMAIL", "a@b.com"), 1)
        self.assertNotEqual(a, b)

    def test_value_not_leaked(self):
        out = HashStrategy().generate(_f("PHONE", "+79161234567"), 1)
        self.assertNotIn("79161234567", out)


# ---------------------------------------------------------------------------
# RemoveStrategy — маркер (пустой по умолчанию)
# ---------------------------------------------------------------------------
class RemoveStrategyTests(unittest.TestCase):
    def test_is_not_reversible(self):
        self.assertFalse(RemoveStrategy.reversible)

    def test_default_marker_is_empty(self):
        self.assertEqual(RemoveStrategy().generate(_f("EMAIL", "a@b.com"), 1), "")

    def test_custom_marker(self):
        out = RemoveStrategy("[REDACTED]").generate(_f("EMAIL", "a@b.com"), 1)
        self.assertEqual(out, "[REDACTED]")

    def test_marker_constant_regardless_of_finding(self):
        s = RemoveStrategy("X")
        self.assertEqual(s.generate(_f("EMAIL", "a"), 1), "X")
        self.assertEqual(s.generate(_f("PHONE", "b"), 9), "X")


# ---------------------------------------------------------------------------
# make_strategy — фабрика
# ---------------------------------------------------------------------------
class MakeStrategyTests(unittest.TestCase):
    def test_strategies_tuple_contents(self):
        self.assertEqual(
            STRATEGIES, ("placeholder", "pseudonym", "partial", "hash", "remove")
        )

    def test_default_name_is_placeholder(self):
        self.assertIsInstance(make_strategy(), PlaceholderStrategy)

    def test_each_known_name_maps_to_class(self):
        self.assertIsInstance(make_strategy("placeholder"), PlaceholderStrategy)
        self.assertIsInstance(make_strategy("pseudonym"), PseudonymStrategy)
        self.assertIsInstance(make_strategy("partial"), PartialStrategy)
        self.assertIsInstance(make_strategy("hash"), HashStrategy)
        self.assertIsInstance(make_strategy("remove"), RemoveStrategy)

    def test_all_strategy_names_buildable(self):
        for name in STRATEGIES:
            self.assertTrue(hasattr(make_strategy(name), "generate"))

    def test_template_passed_to_placeholder(self):
        s = make_strategy("placeholder", template="{type}#{n}")
        self.assertEqual(s.generate(_f("EMAIL", "a"), 5), "EMAIL#5")

    def test_key_passed_to_pseudonym(self):
        a = make_strategy("pseudonym", key="alpha").generate(_f("EMAIL", "a@b.com"), 1)
        b = make_strategy("pseudonym", key="beta").generate(_f("EMAIL", "a@b.com"), 1)
        self.assertNotEqual(a, b)

    def test_key_passed_to_hash(self):
        a = make_strategy("hash", key="alpha").generate(_f("EMAIL", "a@b.com"), 1)
        b = make_strategy("hash", key="beta").generate(_f("EMAIL", "a@b.com"), 1)
        self.assertNotEqual(a, b)

    def test_visible_and_mask_char_passed_to_partial(self):
        s = make_strategy("partial", visible=2, mask_char="#")
        self.assertEqual(s.generate(_f("X", "abcdef"), 1), "####ef")

    def test_marker_passed_to_remove(self):
        s = make_strategy("remove", marker="[X]")
        self.assertEqual(s.generate(_f("X", "v"), 1), "[X]")

    def test_unknown_name_raises_value_error(self):
        with self.assertRaises(ValueError):
            make_strategy("bogus")

    def test_unknown_name_message_lists_available(self):
        with self.assertRaises(ValueError) as ctx:
            make_strategy("nope")
        msg = str(ctx.exception)
        for name in STRATEGIES:
            self.assertIn(name, msg)

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            make_strategy("")

    def test_name_is_case_sensitive(self):
        with self.assertRaises(ValueError):
            make_strategy("Placeholder")


# ---------------------------------------------------------------------------
# datashield.formats — низкоуровневые генераторы
# ---------------------------------------------------------------------------
class FormatsTests(unittest.TestCase):
    def test_byte_stream_deterministic_and_bytes(self):
        a = [next(byte_stream("seed")) for _ in range(40)]
        b = [next(byte_stream("seed")) for _ in range(40)]
        self.assertEqual(a, b)
        self.assertTrue(all(0 <= x <= 255 for x in a))

    def test_byte_stream_crosses_block_boundary(self):
        # Один блок sha256 = 32 байта; берём больше, проверяем что не падает.
        vals = []
        gen = byte_stream("x")
        for _ in range(100):
            vals.append(next(gen))
        self.assertEqual(len(vals), 100)

    def test_byte_stream_different_seed_differs(self):
        a = [next(byte_stream("s1")) for _ in range(32)]
        b = [next(byte_stream("s2")) for _ in range(32)]
        self.assertNotEqual(a, b)

    def test_map_digits_preserves_separators_and_length(self):
        out = map_digits("123-45-6789", "seed")
        self.assertEqual(len(out), len("123-45-6789"))
        self.assertEqual(out[3], "-")
        self.assertEqual(out[6], "-")
        self.assertTrue(all(c.isdigit() for c in out if c != "-"))

    def test_map_digits_no_digits_returns_original(self):
        self.assertEqual(map_digits("abc.def", "seed"), "abc.def")

    def test_map_digits_first_digit_never_zero(self):
        out = map_digits("00000000", "seed-that-could-start-zero")
        self.assertNotEqual(out[0], "0")

    def test_map_digits_deterministic(self):
        self.assertEqual(map_digits("9999", "s"), map_digits("9999", "s"))

    def test_map_digits_luhn_makes_valid(self):
        out = map_digits("4111111111111111", "s", luhn=True)
        self.assertTrue(luhn_check(out))

    def test_fake_card_is_luhn_valid(self):
        self.assertTrue(luhn_check(fake_card("4111111111111111", "s")))

    def test_fake_email_form(self):
        out = fake_email("s")
        self.assertTrue(out.startswith("user"))
        self.assertTrue(out.endswith("@example.invalid"))

    def test_fake_email_deterministic(self):
        self.assertEqual(fake_email("seed"), fake_email("seed"))
        self.assertNotEqual(fake_email("a"), fake_email("b"))

    def test_fake_phone_preserves_form(self):
        out = fake_phone("+7 (916) 123-45-67", "s")
        original = "+7 (916) 123-45-67"
        self.assertEqual(len(out), len(original))
        for i, c in enumerate(original):
            if not c.isdigit():
                self.assertEqual(out[i], c)

    def test_fake_person_word_count_preserved(self):
        self.assertEqual(len(fake_person("Ivan Petrov", "s").split()), 2)
        self.assertEqual(len(fake_person("John", "s").split()), 1)

    def test_fake_person_ascii_vs_cyrillic_pool(self):
        # ASCII-имя берётся из EN-пула (латиница), кириллическое — из RU-пула.
        en = fake_person("John", "seedX")
        ru = fake_person("Иван", "seedX")
        self.assertTrue(en[0].isascii())
        self.assertFalse(ru[0].isascii())

    def test_fake_for_type_routes_known_types(self):
        self.assertTrue(luhn_check(fake_for_type("CREDIT_CARD", "4111111111111111", "s")))
        self.assertTrue(fake_for_type("EMAIL", "a@b.com", "s").endswith("@example.invalid"))
        self.assertEqual(len(fake_for_type("PHONE", "+1 555 0000", "s")), len("+1 555 0000"))
        self.assertEqual(len(fake_for_type("PHONE_RU", "+7 900 0000", "s")), len("+7 900 0000"))
        self.assertEqual(len(fake_for_type("PERSON", "Bob Lee", "s").split()), 2)

    def test_fake_for_type_purely_numeric_uses_map_digits(self):
        # Чисто числовое (цифры+пробелы) — формо-сохранно; пробелы сохранены.
        out = fake_for_type("ACCOUNT", "0000 1234 5678", "s")
        self.assertEqual(len(out), len("0000 1234 5678"))
        for i, c in enumerate("0000 1234 5678"):
            if not c.isdigit():
                self.assertEqual(out[i], c)

    def test_fake_for_type_value_with_letters_uses_fresh_token(self):
        # БЕЗОПАСНОСТЬ: значение с буквами -> свежий токен, без утечки.
        out = fake_for_type("WIDGET", "abcdef", "s")
        self.assertEqual(len(out), len("abcdef"))
        self.assertTrue(out.isalnum())
        self.assertNotIn("abcdef", out)

    def test_fake_for_type_deterministic(self):
        self.assertEqual(
            fake_for_type("EMAIL", "a@b.com", "seed"),
            fake_for_type("EMAIL", "a@b.com", "seed"),
        )


# ---------------------------------------------------------------------------
# ReplacementContext — стабильность и vault
# ---------------------------------------------------------------------------
class ReplacementContextTests(unittest.TestCase):
    def test_same_value_same_replacement(self):
        ctx = ReplacementContext(make_strategy("placeholder"))
        a = ctx.replacement_for(_f("EMAIL", "x@y.com", 0))
        b = ctx.replacement_for(_f("EMAIL", "x@y.com", 30))
        self.assertEqual(a, b)
        self.assertEqual(a, "[EMAIL_1]")

    def test_distinct_values_get_distinct_numbers(self):
        ctx = ReplacementContext(make_strategy("placeholder"))
        self.assertEqual(ctx.replacement_for(_f("EMAIL", "a@b.com")), "[EMAIL_1]")
        self.assertEqual(ctx.replacement_for(_f("EMAIL", "c@d.com")), "[EMAIL_2]")

    def test_numbering_is_per_type(self):
        ctx = ReplacementContext(make_strategy("placeholder"))
        self.assertEqual(ctx.replacement_for(_f("EMAIL", "a@b.com")), "[EMAIL_1]")
        self.assertEqual(ctx.replacement_for(_f("PHONE", "123")), "[PHONE_1]")

    def test_mapping_has_no_raw_values(self):
        ctx = ReplacementContext(make_strategy("placeholder"))
        ctx.replacement_for(_f("EMAIL", "secret@b.com"))
        self.assertEqual(ctx.mapping, {"[EMAIL_1]": "EMAIL"})
        self.assertNotIn("secret@b.com", str(ctx.mapping))

    def test_vault_maps_replacement_to_original(self):
        ctx = ReplacementContext(make_strategy("placeholder"))
        ctx.replacement_for(_f("EMAIL", "secret@b.com"))
        self.assertEqual(ctx.vault(), {"[EMAIL_1]": "secret@b.com"})


# ---------------------------------------------------------------------------
# Интеграция: redact(strategy=...) + restore round-trip
# ---------------------------------------------------------------------------
class RedactStrategyIntegrationTests(unittest.TestCase):
    TEXT = "Email me at john.doe@example.com or call +7 916 123-45-67"

    def test_placeholder_default(self):
        r = redact(self.TEXT, strategy="placeholder")
        self.assertIn("[EMAIL_1]", r.masked_text)
        self.assertIn("[PHONE_RU_1]", r.masked_text)
        self.assertNotIn("john.doe@example.com", r.masked_text)

    def test_placeholder_no_vault_without_reversible(self):
        r = redact(self.TEXT, strategy="placeholder")
        self.assertEqual(r.vault, {})

    def test_placeholder_reversible_round_trip(self):
        r = redact(self.TEXT, strategy="placeholder", reversible=True)
        self.assertTrue(r.vault)
        self.assertEqual(r.restore(), self.TEXT)
        self.assertEqual(restore(r.masked_text, r.vault), self.TEXT)

    def test_pseudonym_plausible_and_reversible(self):
        r = redact(self.TEXT, strategy="pseudonym", reversible=True)
        self.assertNotIn("john.doe@example.com", r.masked_text)
        self.assertIn("@example.invalid", r.masked_text)
        self.assertEqual(r.restore(), self.TEXT)

    def test_hash_format_in_output(self):
        r = redact(self.TEXT, strategy="hash", reversible=True)
        self.assertTrue(re.search(r"\[EMAIL_[0-9a-f]{10}\]", r.masked_text))
        self.assertEqual(r.restore(), self.TEXT)

    def test_partial_keeps_tail_masks_rest(self):
        r = redact(self.TEXT, strategy="partial")
        # Хвост последних 4 alnum email видимы (.com -> 'e','c','o','m').
        self.assertIn("e.com", r.masked_text)
        self.assertIn("*", r.masked_text)
        self.assertNotIn("john.doe", r.masked_text)

    def test_remove_default_deletes_values(self):
        r = redact(self.TEXT, strategy="remove")
        self.assertNotIn("john.doe@example.com", r.masked_text)
        self.assertNotIn("+7 916", r.masked_text)
        self.assertTrue(r.masked_text.startswith("Email me at "))

    def test_unknown_strategy_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact(self.TEXT, strategy="nonsense")

    def test_pseudonym_key_from_config_changes_output(self):
        r1 = redact(self.TEXT, Config(pseudonym_key="k1"), strategy="pseudonym")
        r2 = redact(self.TEXT, Config(pseudonym_key="k2"), strategy="pseudonym")
        self.assertNotEqual(r1.masked_text, r2.masked_text)

    def test_stable_replacement_for_repeated_value(self):
        text = "a@b.com talks to a@b.com again"
        r = redact(text, strategy="placeholder")
        # Одно и то же значение -> один и тот же плейсхолдер дважды.
        self.assertEqual(r.masked_text.count("[EMAIL_1]"), 2)
        self.assertNotIn("[EMAIL_2]", r.masked_text)

    def test_scan_finds_without_masking(self):
        findings = scan(self.TEXT)
        types = {f.type for f in findings}
        self.assertIn("EMAIL", types)


if __name__ == "__main__":
    unittest.main()
