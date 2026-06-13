"""Тесты европейских идентификаторов из datashield/detectors/intl_ids.py.

Фокус — поведение детекторов и валидаторов для стран ЕС:

  * Испания  — DNI_ES (буквенный контроль mod-23) и NIE_ES (X/Y/Z + mod-23).
  * Италия   — CODICE_FISCALE (нечёт/чёт таблицы, контрольная буква mod-26).
  * Франция  — FR_NIR (ключ mod-97: key == 97 - body % 97).
  * Польша   — PESEL (keyword-gated: видим ТОЛЬКО при ключевом слове PESEL).
  * Германия — DE_TAX_ID (keyword-gated: видим ТОЛЬКО при steuer/tax-id/idnr).

Все утверждения сверены с фактическим поведением исходников:
  - default min_confidence == 0.7 (datashield/config.py);
  - DNI_ES/NIE_ES/CODICE_FISCALE/FR_NIR включены по умолчанию (conf >= 0.8);
  - PESEL base_confidence == 0.5, DE_TAX_ID base_confidence == 0.45 —
    оба НИЖЕ порога 0.7, поэтому без ключевого слова отфильтровываются движком,
    а с ключевым словом поднимаются до 0.92 / 0.9 и проходят.

FR_NIR-вектор НЕ хардкодится: валидный 15-значный номер строится из 13-значного
тела вычислением ключа mod-97 (см. _make_fr_nir), как требует задача.
"""
import unittest

from datashield import scan
from datashield.validators_intl import (
    validate_codice_fiscale,
    validate_de_taxid,
    validate_dni_es,
    validate_fr_nir,
    validate_nie_es,
    validate_pesel,
)

# --- Известно-валидные векторы (из условия задачи) ---
DNI_VALID = "12345678Z"      # буква mod-23 верна
DNI_INVALID = "12345678A"    # та же цифровая часть, неверная буква
NIE_VALID = "X1234567L"      # X -> префикс 0, mod-23 верна
CF_VALID = "RSSMRA85T10A562S"
CF_TAMPERED = "RSSMRA85T10A562X"  # подменена контрольная буква
PESEL_VALID = "44051401359"
DE_TAX_VALID = "86095742719"


def _make_fr_nir(body13: str) -> str:
    """Достроить валидный 15-значный NIR: ключ = 97 - (body % 97), 2 цифры."""
    assert len(body13) == 13 and body13.isdigit()
    key = 97 - (int(body13) % 97)
    return body13 + f"{key:02d}"


FR_NIR_BODY = "1850575123456"          # мужчина, 1985, мес 05, деп 75, …
FR_NIR_VALID = _make_fr_nir(FR_NIR_BODY)   # -> '185057512345673'
# Тампер: меняем последнюю цифру тела, ключ оставляем прежним → mod-97 ломается.
FR_NIR_TAMPERED = FR_NIR_BODY[:-1] + "7" + FR_NIR_VALID[13:]


def _types(text: str):
    """Множество типов находок при дефолтной конфигурации (min_confidence=0.7)."""
    return {f.type for f in scan(text)}


class SpainDniValidatorTests(unittest.TestCase):
    """validate_dni_es — буквенный контроль по таблице mod-23."""

    def test_valid_dni(self):
        self.assertTrue(validate_dni_es(DNI_VALID))

    def test_invalid_dni_wrong_letter(self):
        # Те же 8 цифр, но буква 'A' не соответствует контролю.
        self.assertFalse(validate_dni_es(DNI_INVALID))

    def test_lowercase_letter_accepted(self):
        # Валидатор приводит к upper() — строчная буква проходит.
        self.assertTrue(validate_dni_es("12345678z"))

    def test_wrong_length_rejected(self):
        self.assertFalse(validate_dni_es("1234567Z"))   # 7 цифр
        self.assertFalse(validate_dni_es("123456789Z"))  # 9 цифр


class SpainDniDetectorTests(unittest.TestCase):
    """DNI_ES включён по умолчанию (conf 0.8) — без ключевого слова."""

    def test_valid_dni_detected(self):
        self.assertIn("DNI_ES", _types("Mi DNI es 12345678Z para el tramite"))

    def test_invalid_dni_not_detected(self):
        # Неверная контрольная буква — валидатор режет находку.
        self.assertNotIn("DNI_ES", _types("Mi DNI es 12345678A para el tramite"))

    def test_bare_valid_dni_detected_without_keyword(self):
        # default-on: ключевое слово не требуется.
        self.assertIn("DNI_ES", _types("12345678Z"))


class SpainNieTests(unittest.TestCase):
    """validate_nie_es + детектор NIE_ES (включён по умолчанию, conf 0.82)."""

    def test_valid_nie_validator(self):
        self.assertTrue(validate_nie_es(NIE_VALID))

    def test_tampered_nie_validator(self):
        # Меняем контрольную букву — mod-23 не сходится.
        self.assertFalse(validate_nie_es("X1234567M"))

    def test_bad_prefix_rejected(self):
        # Только X/Y/Z допустимы как префикс NIE.
        self.assertFalse(validate_nie_es("A1234567L"))

    def test_valid_nie_detected(self):
        self.assertIn("NIE_ES", _types("Numero NIE: X1234567L"))

    def test_tampered_nie_not_detected(self):
        self.assertNotIn("NIE_ES", _types("Numero NIE: X1234567M"))


class ItalyCodiceFiscaleTests(unittest.TestCase):
    """validate_codice_fiscale + детектор CODICE_FISCALE (default-on, conf 0.9)."""

    def test_valid_cf_validator(self):
        self.assertTrue(validate_codice_fiscale(CF_VALID))

    def test_tampered_cf_validator(self):
        # Подменена контрольная буква S -> X.
        self.assertFalse(validate_codice_fiscale(CF_TAMPERED))

    def test_lowercase_cf_validator(self):
        self.assertTrue(validate_codice_fiscale(CF_VALID.lower()))

    def test_wrong_length_rejected(self):
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562"))  # 15 симв.

    def test_valid_cf_detected(self):
        self.assertIn("CODICE_FISCALE", _types("Codice fiscale RSSMRA85T10A562S"))

    def test_tampered_cf_not_detected(self):
        self.assertNotIn(
            "CODICE_FISCALE", _types("Codice fiscale RSSMRA85T10A562X")
        )


class FranceNirTests(unittest.TestCase):
    """validate_fr_nir + детектор FR_NIR (default-on, conf 0.88), ключ mod-97."""

    def test_constructed_nir_is_15_digits(self):
        self.assertEqual(len(FR_NIR_VALID), 15)
        self.assertTrue(FR_NIR_VALID.isdigit())

    def test_valid_nir_validator(self):
        self.assertTrue(validate_fr_nir(FR_NIR_VALID))

    def test_key_matches_mod97(self):
        # Документируем сам инвариант алгоритма: key == 97 - body % 97.
        body, key = FR_NIR_VALID[:13], int(FR_NIR_VALID[13:])
        self.assertEqual(97 - (int(body) % 97), key)

    def test_tampered_nir_validator(self):
        self.assertFalse(validate_fr_nir(FR_NIR_TAMPERED))

    def test_wrong_length_rejected(self):
        self.assertFalse(validate_fr_nir(FR_NIR_VALID[:-1]))  # 14 цифр

    def test_valid_nir_detected(self):
        self.assertIn("FR_NIR", _types("Numero de securite sociale " + FR_NIR_VALID))

    def test_tampered_nir_not_detected(self):
        self.assertNotIn("FR_NIR", _types("Numero " + FR_NIR_TAMPERED))


class PolandPeselKeywordGateTests(unittest.TestCase):
    """PESEL keyword-gated: base 0.5 < 0.7 → виден ТОЛЬКО при слове PESEL."""

    def test_pesel_validator_valid(self):
        self.assertTrue(validate_pesel(PESEL_VALID))

    def test_pesel_present_with_keyword(self):
        self.assertIn("PESEL", _types("PESEL: " + PESEL_VALID))

    def test_pesel_absent_without_keyword(self):
        # Голая 11-значная последовательность не достаёт до порога 0.7 и
        # не матчится другими детекторами — находок нет вовсе.
        self.assertEqual(_types("Numer to " + PESEL_VALID), set())

    def test_pesel_absent_when_keyword_too_far(self):
        # Окно контекста — 25 символов; слово дальше не поднимает уверенность.
        far = "PESEL" + " " * 40 + PESEL_VALID
        self.assertNotIn("PESEL", _types(far))


class GermanyTaxIdKeywordGateTests(unittest.TestCase):
    """DE_TAX_ID keyword-gated: base 0.45 < 0.7 → виден ТОЛЬКО при steuer/tax-id."""

    def test_de_taxid_validator_valid(self):
        self.assertTrue(validate_de_taxid(DE_TAX_VALID))

    def test_de_taxid_present_with_steuer_keyword(self):
        self.assertIn("DE_TAX_ID", _types("Steuer-ID " + DE_TAX_VALID))

    def test_de_taxid_present_with_idnr_keyword(self):
        self.assertIn("DE_TAX_ID", _types("IdNr " + DE_TAX_VALID))

    def test_de_taxid_absent_without_keyword(self):
        # Без ключевого слова DE_TAX_ID не появляется. Сама 11-значная строка
        # при этом перехватывается детектором PHONE_RU — фиксируем фактическое
        # поведение: DE_TAX_ID отсутствует, но множество находок НЕ пустое.
        types = _types("Nummer ist " + DE_TAX_VALID)
        self.assertNotIn("DE_TAX_ID", types)
        self.assertIn("PHONE_RU", types)

    def test_pesel_keyword_does_not_unlock_de_taxid(self):
        # Ключевое слово PESEL не относится к немецкому детектору: для DE-номера
        # рядом с 'PESEL' DE_TAX_ID не выстреливает (а validate_pesel(de)=False).
        types = _types("PESEL " + DE_TAX_VALID)
        self.assertNotIn("DE_TAX_ID", types)
        self.assertNotIn("PESEL", types)


if __name__ == "__main__":
    unittest.main()
