"""Тесты детекторов из datashield/detectors/extra.py.

Покрываем дополнительные идентификаторы:
  * РФ: ОГРН (13, контрольная цифра), ОГРНИП (15, контрольная цифра),
    КПП, БИК, расчётный счёт, полис ОМС, водительское удостоверение —
    контекстно-зависимые ловятся ТОЛЬКО при ключевом слове рядом.
  * Международные: US_SSN, US_EIN (по ключевому слову EIN), UK_NINO,
    ETH_ADDRESS, BTC_ADDRESS.

Особое внимание: ETH-адрес (0x + 40 hex) маскируется ЦЕЛИКОМ как
ETH_ADDRESS, а не частично как CREDIT_CARD.
"""
import unittest

from datashield import redact, scan
from datashield.detectors import extra
from datashield.validators import validate_ogrn, validate_ogrnip


def types_in(text, **kwargs):
    return {f.type for f in scan(text, **kwargs)}


def findings_of(text, type_, **kwargs):
    return [f for f in scan(text, **kwargs) if f.type == type_]


# --- заранее посчитанные валидные значения (контрольная цифра корректна) ---
# ОГРН: control = int(first12) % 11 % 10
VALID_OGRN = "1027700132932"          # 13 цифр, валидная контрольная цифра
# ОГРНИП: control = int(first14) % 13 % 10
VALID_OGRNIP = "304502310050001"      # 15 цифр, валидная контрольная цифра


class ValidValuesSanityTests(unittest.TestCase):
    """Подстраховка: используемые в тестах значения действительно валидны."""

    def test_valid_ogrn_passes_validator(self):
        self.assertTrue(validate_ogrn(VALID_OGRN))
        self.assertEqual(len(VALID_OGRN), 13)

    def test_valid_ogrnip_passes_validator(self):
        self.assertTrue(validate_ogrnip(VALID_OGRNIP))
        self.assertEqual(len(VALID_OGRNIP), 15)


class OgrnTests(unittest.TestCase):
    """ОГРН — 13 цифр, RegexDetector с проверкой контрольной цифры."""

    def test_valid_ogrn_with_keyword(self):
        self.assertIn("OGRN", types_in("ОГРН " + VALID_OGRN + " компании"))

    def test_valid_ogrn_without_keyword_still_detected(self):
        # conf 0.85 >= порога 0.7, контрольная цифра валидна → ловится и без слова.
        self.assertIn("OGRN", types_in("номер " + VALID_OGRN + " в реестре"))

    def test_ogrn_bad_control_digit_not_detected(self):
        # Та же база, но контрольная цифра испорчена → отбраковка валидатором.
        bad = VALID_OGRN[:12] + str((int(VALID_OGRN[12]) + 1) % 10)
        self.assertNotIn("OGRN", types_in("ОГРН " + bad))

    def test_ogrn_is_not_ogrnip(self):
        # 13-значный валидный ОГРН не должен попадать в OGRNIP (15 цифр).
        self.assertNotIn("OGRNIP", types_in(VALID_OGRN))

    def test_ogrn_value_and_span(self):
        text = "ОГРН " + VALID_OGRN + " конец"
        hits = findings_of(text, "OGRN")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, VALID_OGRN)
        self.assertEqual(text[hits[0].start:hits[0].end], VALID_OGRN)

    def test_twelve_digits_not_ogrn(self):
        self.assertNotIn("OGRN", types_in("число 102770013293 тут"))

    def test_fourteen_digits_not_ogrn(self):
        # 14 цифр подряд: границы \d не дадут вырезать 13.
        self.assertNotIn("OGRN", types_in("12345678901234"))


class OgrnipTests(unittest.TestCase):
    """ОГРНИП — 15 цифр, RegexDetector с проверкой контрольной цифры."""

    def test_valid_ogrnip_with_keyword(self):
        self.assertIn("OGRNIP", types_in("ОГРНИП " + VALID_OGRNIP + " ИП"))

    def test_valid_ogrnip_without_keyword_still_detected(self):
        self.assertIn("OGRNIP", types_in("идентификатор " + VALID_OGRNIP))

    def test_ogrnip_bad_control_digit_not_detected(self):
        bad = VALID_OGRNIP[:14] + str((int(VALID_OGRNIP[14]) + 1) % 10)
        self.assertNotIn("OGRNIP", types_in("ОГРНИП " + bad))

    def test_ogrnip_is_not_ogrn(self):
        # 15-значный ОГРНИП не должен также попадать в OGRN (13 цифр).
        self.assertNotIn("OGRN", types_in(VALID_OGRNIP))

    def test_ogrnip_value_and_span(self):
        hits = findings_of(VALID_OGRNIP, "OGRNIP")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, VALID_OGRNIP)


class KppTests(unittest.TestCase):
    """КПП — ловится только при ключевом слове «КПП» рядом."""

    def test_kpp_with_keyword(self):
        self.assertIn("KPP", types_in("КПП 770701001 организации"))

    def test_kpp_without_keyword_not_detected(self):
        # base_confidence 0.4 < порога 0.7 → без слова не маскируется.
        self.assertNotIn("KPP", types_in("код 770701001 в форме"))

    def test_kpp_with_letters_in_middle(self):
        # Формат \d{4}[0-9A-Z]{2}\d{3} допускает буквы в середине.
        self.assertIn("KPP", types_in("КПП 7707AB001 указан"))

    def test_kpp_keyword_case_insensitive(self):
        # keyword компилируется с re.IGNORECASE.
        self.assertIn("KPP", types_in("кпп 770701001"))


class BicTests(unittest.TestCase):
    """БИК — 9 цифр, начинается с 04, ловится только при слове «БИК»."""

    def test_bic_with_keyword(self):
        self.assertIn("BIC", types_in("БИК 044525225 банка"))

    def test_bic_without_keyword_not_detected(self):
        self.assertNotIn("BIC", types_in("число 044525225 здесь"))

    def test_bic_not_starting_with_04_not_detected(self):
        # Шаблон требует префикс 04; 12-значный? нет — 9 цифр, но не 04…
        self.assertNotIn("BIC", types_in("БИК 123456789"))

    def test_bic_keyword_case_insensitive(self):
        self.assertIn("BIC", types_in("бик 044525225"))


class BankAccountTests(unittest.TestCase):
    """Расчётный счёт — 20 цифр, ключевые слова счёт/счет/р/с/расчётн."""

    ACC = "40702810500000012345"

    def test_account_with_schet_keyword(self):
        self.assertIn("BANK_ACCOUNT", types_in("счёт " + self.ACC))

    def test_account_with_schet_no_yo(self):
        self.assertIn("BANK_ACCOUNT", types_in("счет " + self.ACC))

    def test_account_with_rs_keyword(self):
        self.assertIn("BANK_ACCOUNT", types_in("р/с " + self.ACC))

    def test_account_with_raschetn_keyword(self):
        self.assertIn("BANK_ACCOUNT", types_in("расчётный " + self.ACC))

    def test_account_without_keyword_not_detected(self):
        self.assertNotIn("BANK_ACCOUNT", types_in("число " + self.ACC))

    def test_nineteen_digits_not_account(self):
        self.assertNotIn("BANK_ACCOUNT", types_in("счёт 4070281050000001234"))


class OmsPolicyTests(unittest.TestCase):
    """Полис ОМС — 16 цифр, ключевые слова полис/ОМС."""

    OMS = "1234567890123456"

    def test_oms_with_polis_keyword(self):
        self.assertIn("OMS_POLICY", types_in("полис " + self.OMS))

    def test_oms_with_oms_keyword(self):
        self.assertIn("OMS_POLICY", types_in("ОМС " + self.OMS))

    def test_oms_without_keyword_not_detected(self):
        self.assertNotIn("OMS_POLICY", types_in("значение " + self.OMS))

    def test_oms_beats_credit_card_on_keyword(self):
        # 16-значный номер, валидный по Луна, мог бы стать CREDIT_CARD,
        # но boosted 0.92 > card 0.9 → побеждает OMS_POLICY (один матч).
        text = "полис ОМС 4111111111111111"
        found = types_in(text)
        self.assertIn("OMS_POLICY", found)
        self.assertNotIn("CREDIT_CARD", found)


class DriverLicenseRuTests(unittest.TestCase):
    """Водительское удостоверение РФ — ключевые слова водительск/удостоверен/ВУ/права."""

    DL = "12 34 567890"

    def test_dl_with_voditelsk_keyword(self):
        self.assertIn("DRIVER_LICENSE_RU", types_in("водительское " + self.DL))

    def test_dl_with_udostoveren_keyword(self):
        self.assertIn("DRIVER_LICENSE_RU", types_in("удостоверение " + self.DL))

    def test_dl_with_vu_keyword(self):
        self.assertIn("DRIVER_LICENSE_RU", types_in("ВУ " + self.DL))

    def test_dl_with_prava_keyword(self):
        self.assertIn("DRIVER_LICENSE_RU", types_in("права " + self.DL))

    def test_dl_without_keyword_not_detected(self):
        self.assertNotIn("DRIVER_LICENSE_RU", types_in("код " + self.DL))

    def test_dl_without_spaces(self):
        # Пробелы в шаблоне опциональны (\s?).
        self.assertIn("DRIVER_LICENSE_RU", types_in("водительское 1234567890"))


class UsSsnTests(unittest.TestCase):
    """US SSN — формат 123-45-6789, контекстно-зависимый (нужно слово SSN/social).

    Формат совпадает с артикулами/тикетами, поэтому без ключевого слова рядом
    не маскируется — иначе слишком много ложных срабатываний.
    """

    def test_ssn_detected(self):
        self.assertIn("US_SSN", types_in("SSN 123-45-6789 on file"))

    def test_ssn_without_keyword_not_detected(self):
        # Без слова SSN/social — это может быть артикул, не маскируем.
        self.assertNotIn("US_SSN", types_in("число 123-45-6789 тут"))

    def test_ssn_value_and_span(self):
        text = "SSN 078-05-1120 end"
        hits = findings_of(text, "US_SSN")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "078-05-1120")

    def test_ssn_wrong_grouping_not_detected(self):
        # 4-2-4 не соответствует шаблону 3-2-4.
        self.assertNotIn("US_SSN", types_in("номер 1234-56-7890"))

    def test_ssn_no_dashes_not_detected(self):
        self.assertNotIn("US_SSN", types_in("число 123456789 тут"))


class UsEinTests(unittest.TestCase):
    """US EIN — формат 12-3456789, ловится только при ключевом слове EIN."""

    EIN = "12-3456789"

    def test_ein_with_keyword(self):
        self.assertIn("US_EIN", types_in("EIN " + self.EIN))

    def test_ein_without_keyword_not_detected(self):
        # base 0.4 < порога → без слова EIN не маскируется.
        self.assertNotIn("US_EIN", types_in("код " + self.EIN))

    def test_ein_keyword_case_insensitive(self):
        self.assertIn("US_EIN", types_in("ein " + self.EIN))

    def test_ein_wrong_format_not_detected(self):
        # 3-7 вместо 2-7.
        self.assertNotIn("US_EIN", types_in("EIN 123-4567890"))


class UkNinoTests(unittest.TestCase):
    """UK NINO — две буквы префикса, 6 цифр, буква суффикса; контекстно-зависимый.

    Как и SSN, формат совпадает с тикетами/референсами, поэтому требует слова
    NINO/national insurance рядом.
    """

    def test_nino_detected(self):
        self.assertIn("UK_NINO", types_in("NINO AB123456C on record"))

    def test_nino_without_keyword_not_detected(self):
        self.assertNotIn("UK_NINO", types_in("номер JK654321D тут"))

    def test_nino_invalid_prefix_letter_not_detected(self):
        # Q запрещена в префиксе шаблоном — не должно срабатывать.
        self.assertNotIn("UK_NINO", types_in("QQ123456C"))

    def test_nino_lowercase_not_detected(self):
        # Шаблон чувствителен к регистру (без re.IGNORECASE).
        self.assertNotIn("UK_NINO", types_in("ab123456c"))

    def test_nino_invalid_suffix_letter_not_detected(self):
        # Суффикс ограничен A-D; E недопустима.
        self.assertNotIn("UK_NINO", types_in("AB123456E"))


class EthAddressTests(unittest.TestCase):
    """ETH-адрес: 0x + 40 hex. Маскируется ЦЕЛИКОМ, не как CREDIT_CARD."""

    ETH = "0x" + "a" * 40

    def test_eth_detected(self):
        self.assertIn("ETH_ADDRESS", types_in("кошелёк " + self.ETH))

    def test_eth_masked_as_whole_address(self):
        # Главный кейс: адрес целиком → ETH_ADDRESS, не частично CREDIT_CARD.
        found = types_in("перевод на " + self.ETH)
        self.assertIn("ETH_ADDRESS", found)
        self.assertNotIn("CREDIT_CARD", found)

    def test_eth_with_embedded_card_digits_still_eth(self):
        # Внутри hex есть валидная по Луна 16-значная последовательность,
        # но границы матча card попадают в более длинный ETH → побеждает ETH.
        eth = "0x" + "4111111111111111" + "b" * 24
        found = types_in("addr " + eth)
        self.assertIn("ETH_ADDRESS", found)
        self.assertNotIn("CREDIT_CARD", found)

    def test_eth_redacts_to_single_placeholder(self):
        result = redact("кошелёк " + self.ETH)
        self.assertIn("ETH_ADDRESS", result.stats)
        self.assertEqual(result.stats["ETH_ADDRESS"], 1)
        self.assertNotIn(self.ETH, result.masked_text)
        self.assertIn("[ETH_ADDRESS_1]", result.masked_text)

    def test_eth_value_is_full_match(self):
        text = "to " + self.ETH + " now"
        hits = findings_of(text, "ETH_ADDRESS")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, self.ETH)

    def test_eth_uppercase_hex(self):
        eth = "0x" + "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
        self.assertEqual(len(eth), 42)
        self.assertIn("ETH_ADDRESS", types_in("addr " + eth))

    def test_eth_too_short_not_detected(self):
        # 39 hex вместо 40.
        self.assertNotIn("ETH_ADDRESS", types_in("0x" + "a" * 39))


class BtcAddressTests(unittest.TestCase):
    """BTC-адрес: legacy (1.../3...) и bech32 (bc1...)."""

    def test_btc_legacy_p2pkh(self):
        self.assertIn(
            "BTC_ADDRESS",
            types_in("кошелёк 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        )

    def test_btc_bech32(self):
        self.assertIn(
            "BTC_ADDRESS",
            types_in("addr bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
        )

    def test_btc_value_is_full_match(self):
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        hits = findings_of("send to " + addr, "BTC_ADDRESS")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, addr)

    def test_btc_too_short_not_detected(self):
        # Слишком короткая строка после '1' (< 25 символов).
        self.assertNotIn("BTC_ADDRESS", types_in("1ABCdef"))


class DetectorWiringTests(unittest.TestCase):
    """Проверки самого набора детекторов из extra.build()."""

    def test_build_returns_expected_types(self):
        produced = {d.type for d in extra.build()}
        expected = {
            "OGRN", "OGRNIP", "KPP", "BIC", "BANK_ACCOUNT", "OMS_POLICY",
            "DRIVER_LICENSE_RU", "US_SSN", "US_EIN", "UK_NINO",
            "ETH_ADDRESS", "BTC_ADDRESS",
        }
        self.assertEqual(produced, expected)

    def test_build_returns_twelve_detectors(self):
        self.assertEqual(len(extra.build()), 12)

    def test_detector_names_unique(self):
        names = [d.name for d in extra.build()]
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
