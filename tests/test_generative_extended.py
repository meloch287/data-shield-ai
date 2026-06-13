"""Расширенные генеративные тесты (Block F).

Строим ВАЛИДНЫЕ значения многих типов по их собственным алгоритмам контрольных
сумм (ИНН-10/12, СНИЛС, IBAN GB/DE/FR, ОГРН/ОГРНИП, China ID, FR NIR, Aadhaar по
Verhoeff, карты для IIN-префиксов 2/3/4/5/6) и проверяем, что детектор их находит
(с ключевым словом там, где детектор контекстно-зависимый). Затем портим
контрольную цифру и проверяем, что значение НЕ распознаётся как этот тип.

Каждый сгенерированный (и испорченный) образец перепроверяется in-test через сам
валидатор продукта, поэтому баг в генераторе теста не может замаскировать баг в
продукте: мы утверждаем validate_*(value) is True для валидных и is False для
испорченных ПЕРЕД проверкой детекции.

Источники, прочитанные перед написанием:
  datashield/validators.py, datashield/validators_intl.py — алгоритмы контрольных сумм
  datashield/detectors/{regex_intl,ru,extra,intl_ids}.py — детекторы и контекст-гейты
  datashield/engine.py — порог min_confidence=0.7 и разрешение пересечений
"""
import unittest

from datashield import scan
from datashield.validators import (
    luhn_check,
    validate_iban,
    validate_inn,
    validate_ogrn,
    validate_ogrnip,
    validate_snils,
)
from datashield.validators_intl import (
    validate_aadhaar,
    validate_china_id,
    validate_fr_nir,
    verhoeff_check,
)


def types(text):
    """Множество типов, которые детекторы нашли в тексте."""
    return {f.type for f in scan(text)}


def bump_last(s):
    """Изменить последнюю цифру строки на другую (для порчи контрольной цифры)."""
    return s[:-1] + str((int(s[-1]) + 1) % 10)


# --------------------------------------------------------------------------- #
# Генераторы валидных значений (через те же алгоритмы, что и в продукте).
# Намеренно вычисляем контрольные цифры сами, а затем перепроверяем через
# продуктовый валидатор — двойная проверка ловит ошибки генератора.
# --------------------------------------------------------------------------- #
def make_inn10(base9):
    coeffs = (2, 4, 10, 3, 5, 9, 4, 6, 8)
    c = sum(int(base9[i]) * coeffs[i] for i in range(9)) % 11 % 10
    return base9 + str(c)


def make_inn12(base10):
    c1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    c2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    n1 = sum(int(base10[i]) * c1[i] for i in range(10)) % 11 % 10
    s = base10 + str(n1)
    n2 = sum(int(s[i]) * c2[i] for i in range(11)) % 11 % 10
    return s + str(n2)


def make_snils(num9):
    total = sum(int(num9[i]) * (9 - i) for i in range(9))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check == 100:
            check = 0
    return num9 + f"{check:02d}"


def make_ogrn(base12):
    return base12 + str(int(base12) % 11 % 10)


def make_ogrnip(base14):
    return base14 + str(int(base14) % 13 % 10)


def make_china_id(base17):
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    codes = "10X98765432"
    return base17 + codes[sum(int(base17[i]) * weights[i] for i in range(17)) % 11]


def make_fr_nir(body13):
    key = 97 - (int(body13) % 97)
    return body13 + f"{key:02d}"


def make_aadhaar(base11):
    for d in range(10):
        if verhoeff_check(base11 + str(d)):
            return base11 + str(d)
    raise AssertionError("no valid Verhoeff check digit found")


def _iban_check_digits(country, bban):
    """ISO 13616 mod-97: переставляем BBAN+country+'00', буквы -> числа, 98-mod."""
    rearranged = (bban + country + "00").upper()
    converted = "".join(
        ch if ch.isdigit() else str(ord(ch) - 55) for ch in rearranged
    )
    return f"{98 - (int(converted) % 97):02d}"


def make_iban(country, bban):
    return country + _iban_check_digits(country, bban) + bban


def make_card(prefix):
    """Дополнить IIN-префикс нулями до 15 цифр и подобрать цифру Луна."""
    body = prefix + "0" * (15 - len(prefix))
    for d in range(10):
        if luhn_check(body + str(d)):
            return body + str(d)
    raise AssertionError("no valid Luhn check digit found")


# --------------------------------------------------------------------------- #
# Валидные значения -> ДОЛЖНЫ быть найдены как соответствующий тип.
# --------------------------------------------------------------------------- #
class ValidInnDetected(unittest.TestCase):
    def test_inn10_detected_with_keyword(self):
        # ИНН-10 контекстно-зависимый: base_confidence 0.55 < порога 0.7,
        # поэтому без слова «ИНН» не маскируется — слово обязательно.
        for base in ("770708389", "583622845", "002927696"):
            inn = make_inn10(base)
            self.assertTrue(validate_inn(inn), inn)
            self.assertEqual(10, len(inn), inn)
            self.assertIn("INN", types(f"ИНН {inn} организации"), inn)

    def test_inn12_detected_with_keyword(self):
        for base in ("5836228451", "1234567890", "7707083893"):
            inn = make_inn12(base)
            self.assertTrue(validate_inn(inn), inn)
            self.assertEqual(12, len(inn), inn)
            self.assertIn("INN", types(f"ИНН {inn} физлица"), inn)


class ValidSnilsDetected(unittest.TestCase):
    def test_snils_detected_with_keyword(self):
        # Берём номера > 001-001-998, чтобы контрольная сумма реально считалась.
        for num in ("112233445", "463436698", "087654303"):
            snils = make_snils(num)
            self.assertTrue(validate_snils(snils), snils)
            self.assertEqual(11, len(snils), snils)
            self.assertIn("SNILS", types(f"СНИЛС {snils} в анкете"), snils)


class ValidIbanDetected(unittest.TestCase):
    def test_iban_detected_across_countries(self):
        # mod-97 для GB/DE/FR; FR BBAN содержит букву (M) — проверяем смешанный.
        cases = [
            ("GB", "WEST12345698765432"),
            ("DE", "370400440532013000"),
            ("FR", "20041010050500013M02606"),
        ]
        for country, bban in cases:
            iban = make_iban(country, bban)
            self.assertTrue(validate_iban(iban), iban)
            self.assertTrue(iban.startswith(country), iban)
            self.assertIn("IBAN", types(f"IBAN {iban}"), iban)


class ValidOgrnDetected(unittest.TestCase):
    def test_ogrn_detected(self):
        # OGRN — обычный RegexDetector (0.85), находится и без ключевого слова.
        # Берём базы с ведущей 1 (реальный признак юрлица): такие 13-значные
        # значения не проходят Луна, поэтому их не перехватывает credit_card.
        for base in ("102770013219", "120774600055", "115774600099"):
            ogrn = make_ogrn(base)
            self.assertTrue(validate_ogrn(ogrn), ogrn)
            self.assertEqual(13, len(ogrn), ogrn)
            self.assertFalse(luhn_check(ogrn), f"{ogrn} не должен быть валиден по Луна")
            self.assertIn("OGRN", types(f"ОГРН {ogrn} в реестре"), ogrn)

    def test_ogrnip_detected(self):
        for base in ("30452760000001", "30400000000001", "32099900000001"):
            ogrnip = make_ogrnip(base)
            self.assertTrue(validate_ogrnip(ogrnip), ogrnip)
            self.assertEqual(15, len(ogrnip), ogrnip)
            self.assertFalse(luhn_check(ogrnip), ogrnip)
            self.assertIn("OGRNIP", types(f"ОГРНИП {ogrnip} предпринимателя"), ogrnip)


class ValidChinaIdDetected(unittest.TestCase):
    def test_china_id_detected(self):
        # Сильная валидация -> детектор включён по умолчанию, контекст не нужен.
        for base in ("11010119900307123", "44030619851201007", "31010119770512456"):
            cid = make_china_id(base)
            self.assertTrue(validate_china_id(cid), cid)
            self.assertEqual(18, len(cid), cid)
            self.assertIn("CHINA_ID", types(f"身份证 {cid}"), cid)


class ValidFrNirDetected(unittest.TestCase):
    def test_fr_nir_detected(self):
        # FR NIR — RegexDetector с валидатором mod-97, контекст не требуется.
        for body in ("1850178123456", "2900275432109", "1041299001234"):
            nir = make_fr_nir(body)
            self.assertTrue(validate_fr_nir(nir), nir)
            self.assertEqual(15, len(nir), nir)
            self.assertIn("FR_NIR", types(f"NIR {nir}"), nir)


class ValidAadhaarDetected(unittest.TestCase):
    def test_aadhaar_detected(self):
        # Verhoeff; первая цифра не 0/1 (требование validate_aadhaar).
        for base in ("23412341234", "98765432109", "55512345678"):
            aadhaar = make_aadhaar(base)
            self.assertTrue(validate_aadhaar(aadhaar), aadhaar)
            self.assertEqual(12, len(aadhaar), aadhaar)
            self.assertNotIn(aadhaar[0], "01", aadhaar)
            self.assertIn("AADHAAR", types(f"Aadhaar {aadhaar}"), aadhaar)


class ValidCardsDetected(unittest.TestCase):
    def test_cards_across_iin_prefixes(self):
        # IIN 2 (Mir/Mastercard-2), 3 (Amex), 4 (Visa), 5 (Mastercard), 6
        # (Discover/UnionPay) — все диапазоны 2..6, которые принимает валидатор.
        for prefix in ("2221", "34", "37", "4", "51", "55", "6011", "62"):
            card = make_card(prefix)
            self.assertTrue(luhn_check(card), card)
            self.assertEqual(16, len(card), card)
            self.assertIn(int(card[0]), range(2, 7), card)
            self.assertIn("CREDIT_CARD", types(f"карта {card}"), card)


# --------------------------------------------------------------------------- #
# Порча контрольной цифры -> значение НЕ распознаётся как этот тип.
# Каждый испорченный образец сначала проверяется через продуктовый валидатор:
# он ДОЛЖЕН вернуть False, иначе мы испортили его неправильно и тест бессмыслен.
# --------------------------------------------------------------------------- #
class TamperedNotDetected(unittest.TestCase):
    def test_bad_inn10(self):
        inn = make_inn10("770708389")
        bad = bump_last(inn)
        self.assertFalse(validate_inn(bad), bad)
        self.assertNotIn("INN", types(f"ИНН {bad}"), bad)

    def test_bad_inn12(self):
        inn = make_inn12("5836228451")
        bad = bump_last(inn)
        self.assertFalse(validate_inn(bad), bad)
        self.assertNotIn("INN", types(f"ИНН {bad}"), bad)

    def test_bad_snils(self):
        snils = make_snils("463436698")
        bad = bump_last(snils)
        self.assertFalse(validate_snils(bad), bad)
        self.assertNotIn("SNILS", types(f"СНИЛС {bad}"), bad)

    def test_bad_iban(self):
        iban = make_iban("GB", "WEST12345698765432")
        # Портим вторую цифру контрольного поля (позиция 3).
        bad = iban[:2] + str((int(iban[2]) + 1) % 10) + iban[3:]
        self.assertFalse(validate_iban(bad), bad)
        self.assertNotIn("IBAN", types(f"IBAN {bad}"), bad)

    def test_bad_ogrn(self):
        ogrn = make_ogrn("102770013219")
        bad = bump_last(ogrn)
        self.assertFalse(validate_ogrn(bad), bad)
        self.assertNotIn("OGRN", types(f"ОГРН {bad}"), bad)

    def test_bad_ogrnip(self):
        ogrnip = make_ogrnip("30452760000001")
        bad = bump_last(ogrnip)
        self.assertFalse(validate_ogrnip(bad), bad)
        self.assertNotIn("OGRNIP", types(f"ОГРНИП {bad}"), bad)

    def test_bad_china_id(self):
        cid = make_china_id("11010119900307123")
        # Портим цифру тела (а не контрольный символ, который бывает X):
        # контрольная сумма перестаёт сходиться.
        bad = cid[:5] + str((int(cid[5]) + 1) % 10) + cid[6:]
        self.assertEqual(len(cid), len(bad), bad)
        self.assertFalse(validate_china_id(bad), bad)
        self.assertNotIn("CHINA_ID", types(f"身份证 {bad}"), bad)

    def test_bad_fr_nir(self):
        nir = make_fr_nir("1850178123456")
        bad = bump_last(nir)
        self.assertFalse(validate_fr_nir(bad), bad)
        self.assertNotIn("FR_NIR", types(f"NIR {bad}"), bad)

    def test_bad_aadhaar(self):
        aadhaar = make_aadhaar("23412341234")
        bad = bump_last(aadhaar)
        self.assertFalse(validate_aadhaar(bad), bad)
        self.assertNotIn("AADHAAR", types(f"Aadhaar {bad}"), bad)

    def test_bad_cards_across_prefixes(self):
        for prefix in ("4", "51", "2221", "34", "6011"):
            card = make_card(prefix)
            bad = bump_last(card)
            self.assertFalse(luhn_check(bad), bad)
            self.assertNotIn("CREDIT_CARD", types(f"карта {bad}"), bad)


# --------------------------------------------------------------------------- #
# Контекст-гейт: валидное значение БЕЗ ключевого слова и С ним.
# Документируем фактическое поведение порога min_confidence=0.7.
# --------------------------------------------------------------------------- #
class ContextGating(unittest.TestCase):
    def test_inn10_requires_keyword(self):
        # ИНН-10 без слова «ИНН» не маскируется (base_confidence 0.55 < 0.7).
        inn = make_inn10("770708389")
        self.assertTrue(validate_inn(inn), inn)
        self.assertNotIn("INN", types(f"число {inn} просто так"), inn)
        self.assertIn("INN", types(f"ИНН {inn}"), inn)

    def test_snils_detected_even_without_keyword(self):
        # Фактическое поведение: у SNILS base_confidence=0.8 > порога 0.7, поэтому
        # валидный СНИЛС маскируется и без слова «СНИЛС» (слово лишь поднимает
        # уверенность до 0.95). Это отличает его от ИНН-10 (base 0.55), которому
        # ключевое слово обязательно. Проверяем оба случая по фактическому коду.
        snils = make_snils("463436698")
        self.assertTrue(validate_snils(snils), snils)
        self.assertIn("SNILS", types(f"последовательность {snils} тут"), snils)
        self.assertIn("SNILS", types(f"СНИЛС {snils}"), snils)


if __name__ == "__main__":
    unittest.main()
