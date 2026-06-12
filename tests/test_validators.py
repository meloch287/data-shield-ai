"""Тесты валидаторов: известные верные и неверные векторы."""
import unittest

from datashield.validators import (
    luhn_check,
    shannon_entropy,
    validate_iban,
    validate_inn,
    validate_snils,
)


class LuhnTests(unittest.TestCase):
    def test_valid_card(self):
        self.assertTrue(luhn_check("4111111111111111"))
        self.assertTrue(luhn_check("5500005555555559"))

    def test_invalid_card(self):
        self.assertFalse(luhn_check("4111111111111112"))

    def test_too_short(self):
        self.assertFalse(luhn_check("1"))


class InnTests(unittest.TestCase):
    def test_valid_10_digit(self):
        self.assertTrue(validate_inn("7707083893"))  # Сбербанк

    def test_valid_12_digit(self):
        self.assertTrue(validate_inn("500100732259"))

    def test_invalid_control_digit(self):
        self.assertFalse(validate_inn("7707083890"))
        self.assertFalse(validate_inn("500100732251"))

    def test_wrong_length(self):
        self.assertFalse(validate_inn("12345"))

    def test_non_digit(self):
        self.assertFalse(validate_inn("77070838ab"))


class SnilsTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(validate_snils("11223344595"))
        self.assertTrue(validate_snils("112-233-445 95"))

    def test_invalid_control(self):
        self.assertFalse(validate_snils("11223344500"))

    def test_wrong_length(self):
        self.assertFalse(validate_snils("123"))


class IbanTests(unittest.TestCase):
    def test_valid_contiguous(self):
        self.assertTrue(validate_iban("GB82WEST12345698765432"))

    def test_valid_with_spaces(self):
        self.assertTrue(validate_iban("GB82 WEST 1234 5698 7654 32"))

    def test_invalid_checksum(self):
        self.assertFalse(validate_iban("GB00WEST12345698765432"))

    def test_malformed(self):
        self.assertFalse(validate_iban("HELLO"))


class EntropyTests(unittest.TestCase):
    def test_low_entropy(self):
        self.assertLess(shannon_entropy("aaaaaaaa"), 1.0)

    def test_high_entropy(self):
        self.assertGreater(shannon_entropy("aA1!bB2@cC3#dD4$"), 3.0)

    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)


if __name__ == "__main__":
    unittest.main()
