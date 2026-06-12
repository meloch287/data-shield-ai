"""Расширенные тесты валидаторов контрольных сумм.

Фокус — ОГРН/ОГРНИП (алгоритм control = int(first N) % mod % 10),
плюс дополнительные векторы для luhn_check, validate_inn,
validate_snils и validate_iban. Все значения сверены с фактическим
поведением функций в datashield/validators.py.
"""
import unittest

# Импорт публичного API — проверяем, что пакет экспортирует ожидаемое.
from datashield import Config, Finding, build_engine, redact, scan  # noqa: F401
from datashield.validators import (
    luhn_check,
    shannon_entropy,
    validate_iban,
    validate_inn,
    validate_ogrn,
    validate_ogrnip,
    validate_snils,
)


class OgrnTests(unittest.TestCase):
    """ОГРН — 13 знаков, контроль = int(first 12) % 11 % 10."""

    def _ctrl(self, base12: str) -> int:
        return int(base12) % 11 % 10

    def test_valid_real_like(self):
        # Реальные/правдоподобные ОГРН с верной контрольной цифрой.
        valid = [
            "1027700153205",
            "3045001160003",
            "1023500000050",
            "1127746000612",
        ]
        for v in valid:
            with self.subTest(ogrn=v):
                self.assertTrue(validate_ogrn(v))

    def test_valid_computed_boundary(self):
        # Граничные базы: все нули, единица с нулями, все девятки.
        for base12 in ("000000000000", "100000000000", "999999999999"):
            full = base12 + str(self._ctrl(base12))
            with self.subTest(ogrn=full):
                self.assertTrue(validate_ogrn(full))

    def test_valid_control_matches_algorithm(self):
        # Для произвольной базы вычисляем контроль алгоритмом и проверяем.
        for base12 in ("123456789012", "555500001234", "987654321098"):
            full = base12 + str(self._ctrl(base12))
            with self.subTest(ogrn=full):
                self.assertTrue(validate_ogrn(full))

    def test_invalid_corrupted_control(self):
        # Берём валидный ОГРН и портим контрольную цифру.
        for valid in ("1027700153205", "1127746000612", "1023500000050"):
            base12 = valid[:12]
            good = int(valid[12])
            bad = (good + 1) % 10
            corrupted = base12 + str(bad)
            with self.subTest(ogrn=corrupted):
                self.assertFalse(validate_ogrn(corrupted))

    def test_invalid_each_wrong_control_digit(self):
        # Ровно одна цифра 0..9 верна; остальные девять — невалидны.
        base12 = "102770015320"
        correct = self._ctrl(base12)
        for d in range(10):
            full = base12 + str(d)
            with self.subTest(ogrn=full, d=d):
                self.assertEqual(validate_ogrn(full), d == correct)

    def test_invalid_too_short(self):
        self.assertFalse(validate_ogrn("102770015320"))  # 12 знаков
        self.assertFalse(validate_ogrn("123"))

    def test_invalid_too_long(self):
        self.assertFalse(validate_ogrn("10277001532055"))  # 14 знаков

    def test_invalid_non_digit(self):
        self.assertFalse(validate_ogrn("102770015320x"))
        self.assertFalse(validate_ogrn("abcdefghijklm"))
        self.assertFalse(validate_ogrn("1027700 53205"))  # пробел

    def test_invalid_empty(self):
        self.assertFalse(validate_ogrn(""))


class OgrnipTests(unittest.TestCase):
    """ОГРНИП — 15 знаков, контроль = int(first 14) % 13 % 10."""

    def _ctrl(self, base14: str) -> int:
        return int(base14) % 13 % 10

    def test_valid_real_like(self):
        valid = [
            "304500116000038",
            "316552700000011",
            "123456789012343",
        ]
        for v in valid:
            with self.subTest(ogrnip=v):
                self.assertTrue(validate_ogrnip(v))

    def test_valid_boundary(self):
        for base14 in ("00000000000000", "10000000000000", "99999999999999"):
            full = base14 + str(self._ctrl(base14))
            with self.subTest(ogrnip=full):
                self.assertTrue(validate_ogrnip(full))

    def test_valid_control_matches_algorithm(self):
        for base14 in ("12345678901234", "55550000123456", "98765432109876"):
            full = base14 + str(self._ctrl(base14))
            with self.subTest(ogrnip=full):
                self.assertTrue(validate_ogrnip(full))

    def test_invalid_corrupted_control(self):
        for valid in ("304500116000038", "316552700000011", "123456789012343"):
            base14 = valid[:14]
            good = int(valid[14])
            bad = (good + 1) % 10
            corrupted = base14 + str(bad)
            with self.subTest(ogrnip=corrupted):
                self.assertFalse(validate_ogrnip(corrupted))

    def test_invalid_each_wrong_control_digit(self):
        base14 = "30450011600003"
        correct = self._ctrl(base14)
        for d in range(10):
            full = base14 + str(d)
            with self.subTest(ogrnip=full, d=d):
                self.assertEqual(validate_ogrnip(full), d == correct)

    def test_invalid_too_short(self):
        self.assertFalse(validate_ogrnip("30450011600003"))  # 14 знаков
        self.assertFalse(validate_ogrnip("123"))

    def test_invalid_too_long(self):
        self.assertFalse(validate_ogrnip("3045001160000388"))  # 16 знаков

    def test_invalid_non_digit(self):
        self.assertFalse(validate_ogrnip("30450011600003x"))
        self.assertFalse(validate_ogrnip("abcdefghijklmno"))

    def test_invalid_empty(self):
        self.assertFalse(validate_ogrnip(""))

    def test_ogrn_length_rejected_as_ogrnip(self):
        # Корректный 13-значный ОГРН не должен проходить как ОГРНИП.
        self.assertFalse(validate_ogrnip("1027700153205"))


class LuhnExtraTests(unittest.TestCase):
    def test_valid_known(self):
        valid = [
            "79927398713",        # классический пример Луна
            "4012888888881881",   # Visa тест
            "6011111111111117",   # Discover тест
            "378282246310005",    # American Express тест
            "000000",             # все нули — сумма 0, делится на 10
        ]
        for v in valid:
            with self.subTest(number=v):
                self.assertTrue(luhn_check(v))

    def test_valid_with_separators(self):
        # Нецифровые символы игнорируются, остаётся валидная последовательность.
        self.assertTrue(luhn_check("4111-1111-1111-1111"))
        self.assertTrue(luhn_check("4111 1111 1111 1111"))

    def test_invalid_checksum(self):
        self.assertFalse(luhn_check("79927398710"))
        self.assertFalse(luhn_check("4012888888881882"))
        self.assertFalse(luhn_check("1234567890123456"))

    def test_too_few_digits(self):
        self.assertFalse(luhn_check(""))
        self.assertFalse(luhn_check("5"))
        self.assertFalse(luhn_check("abcd"))   # < 2 цифр
        self.assertFalse(luhn_check("a1b"))    # ровно 1 цифра

    def test_two_digit_valid(self):
        # Минимальная длина — 2 цифры; "18" даёт сумму 1+8=9? проверим алгоритм.
        # reversed: idx0='8'->8, idx1='1'*2=2 => 10 -> делится на 10.
        self.assertTrue(luhn_check("18"))
        self.assertFalse(luhn_check("19"))


class InnExtraTests(unittest.TestCase):
    def test_valid_10_digit(self):
        for v in ("7707083893", "7830002293"):
            with self.subTest(inn=v):
                self.assertTrue(validate_inn(v))

    def test_valid_12_digit(self):
        self.assertTrue(validate_inn("500100732259"))

    def test_invalid_control_10(self):
        # Все варианты последней цифры кроме верной — невалидны.
        base = "770708389"
        # верная последняя цифра — 3 (из 7707083893)
        for d in range(10):
            v = base + str(d)
            with self.subTest(inn=v):
                self.assertEqual(validate_inn(v), d == 3)

    def test_invalid_control_12(self):
        self.assertFalse(validate_inn("500100732251"))
        self.assertFalse(validate_inn("500100732250"))

    def test_wrong_length(self):
        self.assertFalse(validate_inn("12345"))
        self.assertFalse(validate_inn("77070838931"))   # 11 цифр
        self.assertFalse(validate_inn("5001007322590"))  # 13 цифр
        self.assertFalse(validate_inn(""))

    def test_non_digit(self):
        self.assertFalse(validate_inn("77070838ab"))
        self.assertFalse(validate_inn("7707 083893"))  # пробел
        self.assertFalse(validate_inn("+7707083893"))


class SnilsExtraTests(unittest.TestCase):
    def test_valid_plain(self):
        self.assertTrue(validate_snils("11223344595"))

    def test_valid_formatted(self):
        # Разделители вычищаются регуляркой \D.
        self.assertTrue(validate_snils("112-233-445 95"))
        self.assertTrue(validate_snils("112 233 445 95"))

    def test_low_number_always_valid(self):
        # number <= 001-001-998 -> контроль не рассчитывается, любой хвост ок.
        for ctrl in ("00", "99", "42"):
            v = "001001998" + ctrl
            with self.subTest(snils=v):
                self.assertTrue(validate_snils(v))

    def test_boundary_above_threshold_computes(self):
        # number = 001001999 (1001999 > 1001998) -> рассчитывается контроль,
        # хвост "00" неверен.
        self.assertFalse(validate_snils("00100199900"))

    def test_invalid_control(self):
        self.assertFalse(validate_snils("11223344500"))
        self.assertFalse(validate_snils("11223344594"))

    def test_wrong_length(self):
        self.assertFalse(validate_snils("123"))
        self.assertFalse(validate_snils("112-233-445"))   # 9 цифр после чистки
        self.assertFalse(validate_snils("112233445950"))  # 12 цифр
        self.assertFalse(validate_snils(""))


class IbanExtraTests(unittest.TestCase):
    def test_valid_known(self):
        valid = [
            "GB82WEST12345698765432",
            "DE89370400440532013000",
            "FR1420041010050500013M02606",
        ]
        for v in valid:
            with self.subTest(iban=v):
                self.assertTrue(validate_iban(v))

    def test_valid_with_spaces(self):
        self.assertTrue(validate_iban("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(validate_iban("DE89 3704 0044 0532 0130 00"))

    def test_valid_lowercase(self):
        # Приводится к верхнему регистру перед проверкой.
        self.assertTrue(validate_iban("de89370400440532013000"))
        self.assertTrue(validate_iban("gb82west12345698765432"))

    def test_invalid_checksum(self):
        self.assertFalse(validate_iban("GB00WEST12345698765432"))
        self.assertFalse(validate_iban("DE00370400440532013000"))

    def test_malformed_structure(self):
        self.assertFalse(validate_iban("HELLO"))
        self.assertFalse(validate_iban(""))
        self.assertFalse(validate_iban("AB12"))                  # нет тела
        self.assertFalse(validate_iban("1234WEST12345698765432"))  # цифры вместо страны
        self.assertFalse(validate_iban("GBWEST12345698765432"))    # нет контрольных цифр

    def test_invalid_special_chars(self):
        self.assertFalse(validate_iban("GB82WEST1234569876543!"))
        self.assertFalse(validate_iban("GB82-WEST-1234-5698"))  # дефисы не пробелы


class EntropySanityTests(unittest.TestCase):
    def test_uniform_string_is_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_two_symbols_one_bit(self):
        # 4 'a' и 4 'b' -> ровно 1 бит на символ.
        self.assertAlmostEqual(shannon_entropy("aaaabbbb"), 1.0, places=9)

    def test_random_like_high(self):
        self.assertGreater(shannon_entropy("aA1!bB2@cC3#dD4$"), 3.0)


if __name__ == "__main__":
    unittest.main()
