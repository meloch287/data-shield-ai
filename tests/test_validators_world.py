"""Исчерпывающие тесты datashield.validators_world.

Для каждого валидатора: верный вектор, неверная контрольная сумма, неверная
длина, нецифровой ввод. Для TFN / MyNumber / RRN валидные образцы строятся
вычислением контрольной цифры по алгоритму валидатора и ПЕРЕПРОВЕРЯЮТСЯ в тесте.
Каталожные счётчики не зашиты — вычисляются из build_catalog.

Известные верные векторы (из задания):
  CPF  11144477735 ; CNPJ 11222333000181 ; SIN 046454286 ;
  VIN  1HGBH41JXMN109186 ; CURP HEGG560427MVZRRL04.
"""
import unittest

from datashield.config import Config
from datashield.detectors.registry import build_catalog
from datashield.validators_world import (
    validate_cnpj,
    validate_cpf,
    validate_curp_mx,
    validate_mynumber_jp,
    validate_rrn_kr,
    validate_sin_ca,
    validate_tfn_au,
    validate_tron,
    validate_vin,
)

# --- Сборщики валидных образцов с вычислением контрольной цифры ------------

def _build_tfn(base: str) -> str:
    """Дополняет base (7 или 8 цифр) контрольной так, чтобы взвеш. сумма %11==0.

    Алгоритм валидатора: weights = (1,4,3,7,5,8,6,9,10)[:len], сумма % 11 == 0.
    Для 8-значного TFN последняя цифра имеет вес 9; для 9-значного — вес 10.
    """
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    n = len(base)
    last_weight = weights[n]
    partial = sum(int(base[i]) * weights[i] for i in range(n))
    for last in range(10):
        if (partial + last * last_weight) % 11 == 0:
            return base + str(last)
    raise AssertionError(f"нет однозначной контрольной для TFN base={base!r}")


def _build_mynumber(base: str) -> str:
    """Дополняет base (11 цифр) контрольной цифрой по алгоритму My Number."""
    assert len(base) == 11
    total = sum(int(base[i]) * (i + 2 if i < 6 else i - 4) for i in range(11))
    rem = total % 11
    check = 0 if rem <= 1 else 11 - rem
    return base + str(check)


def _build_rrn(base: str) -> str:
    """Дополняет base (12 цифр) контрольной цифрой по алгоритму RRN (KR)."""
    assert len(base) == 12
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    total = sum(int(base[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10
    return base + str(check)


class CpfTests(unittest.TestCase):
    def test_valid_known_vector(self):
        self.assertTrue(validate_cpf("11144477735"))

    def test_valid_with_separators(self):
        # _digits извлекает только цифры, формат с точками/дефисом проходит.
        self.assertTrue(validate_cpf("111.444.777-35"))

    def test_invalid_checksum(self):
        # Меняем последнюю контрольную цифру — должен отвергнуть.
        self.assertFalse(validate_cpf("11144477736"))

    def test_rejects_all_same_digit(self):
        self.assertFalse(validate_cpf("11111111111"))
        self.assertFalse(validate_cpf("00000000000"))

    def test_wrong_length(self):
        self.assertFalse(validate_cpf("1114447773"))   # 10 цифр
        self.assertFalse(validate_cpf("111444777350"))  # 12 цифр

    def test_non_digit(self):
        # Буквы вырезаются _digits, остаётся неверная длина.
        self.assertFalse(validate_cpf("abcdefghijk"))


class CnpjTests(unittest.TestCase):
    def test_valid_known_vector(self):
        self.assertTrue(validate_cnpj("11222333000181"))

    def test_valid_with_separators(self):
        self.assertTrue(validate_cnpj("11.222.333/0001-81"))

    def test_invalid_checksum(self):
        self.assertFalse(validate_cnpj("11222333000182"))

    def test_rejects_all_same_digit(self):
        self.assertFalse(validate_cnpj("11111111111111"))

    def test_wrong_length(self):
        self.assertFalse(validate_cnpj("1122233300018"))    # 13 цифр
        self.assertFalse(validate_cnpj("112223330001811"))  # 15 цифр

    def test_non_digit(self):
        self.assertFalse(validate_cnpj("abcdefghijklmn"))


class SinCaTests(unittest.TestCase):
    def test_valid_known_vector(self):
        # SIN = длина 9 + Луна.
        self.assertTrue(validate_sin_ca("046454286"))

    def test_is_luhn_based(self):
        # Подтверждаем, что валидатор именно по Луну: ломаем Луна-сумму.
        self.assertFalse(validate_sin_ca("046454287"))

    def test_invalid_checksum(self):
        self.assertFalse(validate_sin_ca("046454285"))

    def test_wrong_length(self):
        self.assertFalse(validate_sin_ca("04645428"))    # 8 цифр
        self.assertFalse(validate_sin_ca("0464542860"))  # 10 цифр

    def test_non_digit(self):
        self.assertFalse(validate_sin_ca("04645428a"))   # → 8 цифр, неверная длина


class TfnAuTests(unittest.TestCase):
    def test_valid_9_digit_constructed(self):
        tfn = _build_tfn("12345678")
        # Перепроверяем построенный образец валидатором.
        self.assertTrue(validate_tfn_au(tfn))
        self.assertEqual(len(tfn), 9)

    def test_valid_8_digit_constructed(self):
        tfn = _build_tfn("1234567")
        self.assertTrue(validate_tfn_au(tfn))
        self.assertEqual(len(tfn), 8)

    def test_valid_with_spaces(self):
        tfn = _build_tfn("1234567")  # 8 цифр
        spaced = tfn[:3] + " " + tfn[3:6] + " " + tfn[6:]
        self.assertTrue(validate_tfn_au(spaced))

    def test_invalid_checksum(self):
        tfn = _build_tfn("12345678")  # валидный 9-значный
        digits = [int(c) for c in tfn]
        digits[-1] = (digits[-1] + 1) % 10
        bad = "".join(str(d) for d in digits)
        self.assertNotEqual(bad, tfn)
        self.assertFalse(validate_tfn_au(bad))

    def test_wrong_length(self):
        self.assertFalse(validate_tfn_au("1234567"))     # 7 цифр
        self.assertFalse(validate_tfn_au("1234567890"))  # 10 цифр

    def test_non_digit(self):
        self.assertFalse(validate_tfn_au("1234567ab"))   # → 7 цифр, неверная длина


class MyNumberJpTests(unittest.TestCase):
    def test_valid_constructed(self):
        mynum = _build_mynumber("12345678901")
        self.assertTrue(validate_mynumber_jp(mynum))
        self.assertEqual(len(mynum), 12)

    def test_valid_with_spaces(self):
        mynum = _build_mynumber("12345678901")
        spaced = mynum[:4] + " " + mynum[4:8] + " " + mynum[8:]
        self.assertTrue(validate_mynumber_jp(spaced))

    def test_invalid_checksum(self):
        mynum = _build_mynumber("12345678901")
        digits = [int(c) for c in mynum]
        digits[-1] = (digits[-1] + 1) % 10
        bad = "".join(str(d) for d in digits)
        self.assertNotEqual(bad, mynum)
        self.assertFalse(validate_mynumber_jp(bad))

    def test_wrong_length(self):
        self.assertFalse(validate_mynumber_jp("12345678901"))    # 11 цифр
        self.assertFalse(validate_mynumber_jp("1234567890123"))  # 13 цифр

    def test_non_digit(self):
        self.assertFalse(validate_mynumber_jp("12345678901a"))   # → 11 цифр


class RrnKrTests(unittest.TestCase):
    def test_valid_constructed(self):
        rrn = _build_rrn("900101312345")
        self.assertTrue(validate_rrn_kr(rrn))
        self.assertEqual(len(rrn), 13)

    def test_valid_with_hyphen(self):
        rrn = _build_rrn("900101312345")
        hyphenated = rrn[:6] + "-" + rrn[6:]
        self.assertTrue(validate_rrn_kr(hyphenated))

    def test_invalid_checksum(self):
        rrn = _build_rrn("900101312345")
        digits = [int(c) for c in rrn]
        digits[-1] = (digits[-1] + 1) % 10
        bad = "".join(str(d) for d in digits)
        self.assertNotEqual(bad, rrn)
        self.assertFalse(validate_rrn_kr(bad))

    def test_wrong_length(self):
        self.assertFalse(validate_rrn_kr("900101312345"))    # 12 цифр
        self.assertFalse(validate_rrn_kr("90010131234540"))  # 14 цифр

    def test_non_digit(self):
        self.assertFalse(validate_rrn_kr("90010131234a"))    # → 11 цифр


class CurpMxTests(unittest.TestCase):
    def test_valid_known_vector(self):
        self.assertTrue(validate_curp_mx("HEGG560427MVZRRL04"))

    def test_valid_lowercase_input_upcased(self):
        # Валидатор приводит к верхнему регистру внутри.
        self.assertTrue(validate_curp_mx("hegg560427mvzrrl04"))

    def test_invalid_checksum(self):
        # Меняем последнюю контрольную цифру.
        self.assertFalse(validate_curp_mx("HEGG560427MVZRRL05"))

    def test_wrong_length(self):
        self.assertFalse(validate_curp_mx("HEGG560427MVZRR"))      # короче 18
        self.assertFalse(validate_curp_mx("HEGG560427MVZRRL040"))  # длиннее 18

    def test_non_digit_in_digit_block(self):
        # Структурный regex требует цифры в позициях даты/контроля.
        self.assertFalse(validate_curp_mx("HEGGAB0427MVZRRL04"))


class VinTests(unittest.TestCase):
    KNOWN = "1HGBH41JXMN109186"  # контрольный знак — буква X в позиции 9 (индекс 8)

    def test_valid_known_vector_with_x_check_digit(self):
        self.assertTrue(validate_vin(self.KNOWN))
        # Подтверждаем, что контрольная позиция действительно 'X'.
        self.assertEqual(self.KNOWN[8], "X")

    def test_rejects_tampered_check_position(self):
        # Подменяем контрольную цифру (индекс 8) — должен отвергнуть.
        tampered = self.KNOWN[:8] + "0" + self.KNOWN[9:]
        self.assertNotEqual(tampered, self.KNOWN)
        self.assertFalse(validate_vin(tampered))

    def test_invalid_checksum_other_position(self):
        # Меняем первую цифру — контрольная сумма больше не сходится.
        altered = "2" + self.KNOWN[1:]
        self.assertFalse(validate_vin(altered))

    def test_wrong_length(self):
        self.assertFalse(validate_vin(self.KNOWN[:16]))      # 16 знаков
        self.assertFalse(validate_vin(self.KNOWN + "0"))     # 18 знаков

    def test_rejects_illegal_letters(self):
        # I, O, Q запрещены структурным regex ISO 3779.
        self.assertFalse(validate_vin("1HGBH41JIMN109186"))  # I вместо X
        self.assertFalse(validate_vin("1HGBH41JOMN109186"))  # O
        self.assertFalse(validate_vin("1HGBH41JQMN109186"))  # Q


class TronValidatorTests(unittest.TestCase):
    VALID = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # реальный mainnet-адрес

    def test_valid_known_address(self):
        self.assertTrue(validate_tron(self.VALID))

    def test_wrong_prefix(self):
        # Не начинается с 'T' → отвергается до декодирования.
        self.assertFalse(validate_tron("X" + self.VALID[1:]))

    def test_wrong_length(self):
        self.assertFalse(validate_tron(self.VALID[:-1]))   # 33 символа
        self.assertFalse(validate_tron(self.VALID + "a"))  # 35 символов

    def test_char_outside_base58_alphabet(self):
        # '0', 'O', 'I', 'l' не входят в алфавит base58 → ValueError → False.
        self.assertFalse(validate_tron("T0" + self.VALID[2:]))
        self.assertFalse(validate_tron("TO" + self.VALID[2:]))

    def test_broken_checksum_is_rejected(self):
        # Меняем последний символ → double-SHA256 не сходится.
        bad = self.VALID[:-1] + ("X" if self.VALID[-1] != "X" else "Y")
        self.assertFalse(validate_tron(bad))

    def test_wrong_version_or_decoded_length(self):
        # Структурно похоже (T + 33 base58), но не настоящий адрес сети TRON:
        # декодируется в неверную длину/версию → отвергается.
        self.assertFalse(validate_tron("T" + "1" * 33))


class CatalogIntegrationTests(unittest.TestCase):
    """Каталог содержит world-типы; счётчики вычисляются, не зашиты."""

    def _types(self):
        return {info.detector.type for info in build_catalog(Config())}

    def test_world_id_types_present(self):
        types = self._types()
        for t in ("CPF_BR", "CNPJ_BR", "RRN_KR", "CURP_MX", "VIN", "TRON_ADDRESS"):
            self.assertIn(t, types)

    def test_keyword_gated_types_present(self):
        types = self._types()
        for t in ("SIN_CA", "TFN_AU", "MYNUMBER_JP", "SOLANA_ADDRESS"):
            self.assertIn(t, types)

    def test_counts_are_positive_and_consistent(self):
        # Вычисляем динамически; проверяем согласованность, а не магические числа.
        catalog = build_catalog(Config())
        total = len(catalog)
        default_on = sum(1 for info in catalog if info.default_enabled)
        types = {info.detector.type for info in catalog}
        self.assertGreater(total, 0)
        self.assertLessEqual(default_on, total)
        self.assertGreater(default_on, 0)
        self.assertLessEqual(len(types), total)


if __name__ == "__main__":
    unittest.main()
