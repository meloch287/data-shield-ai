"""Регресс-тесты на находки адверсариал-аудита (workflow wh90m4pl8).

Каждый кейс соответствует реальной проблеме, найденной агентами и затем
исправленной. Тесты не дают этим проблемам вернуться. Секрето-подобные значения
собираются конкатенацией, чтобы цельный токен не попал в исходник.
"""
import unittest

from datashield import scan


def types_in(text, **kwargs):
    return {f.type for f in scan(text, **kwargs)}


class PrecisionRegressions(unittest.TestCase):
    """Бывшие ложные срабатывания — теперь НЕ должны маскироваться."""

    def test_common_ich_nouns_not_person(self):
        for word in ("Кирпич упал", "вкусный Кулич", "старый Москвич", "Паралич руки"):
            self.assertNotIn("PERSON", types_in(word), word)

    def test_round_number_not_card(self):
        self.assertNotIn("CREDIT_CARD", types_in("Tracking 00000000000000"))
        self.assertNotIn("CREDIT_CARD", types_in("код 1111111111111111"))

    def test_leading_zero_not_card(self):
        # Реальные карты не начинаются с 0.
        self.assertNotIn("CREDIT_CARD", types_in("num 0000111122223333"))

    def test_part_number_not_ssn(self):
        self.assertNotIn("US_SSN", types_in("Part no 123-45-6789 available"))
        self.assertNotIn("US_SSN", types_in("Catalog 078-05-1120"))

    def test_ref_code_not_nino(self):
        self.assertNotIn("UK_NINO", types_in("Code AB123456C"))
        self.assertNotIn("UK_NINO", types_in("Ticket CE654321A"))

    def test_name_homonym_pair_not_person(self):
        for phrase in ("Mark Down the price", "Grace Period applies", "Will Power helps"):
            self.assertNotIn("PERSON", types_in(phrase), phrase)

    def test_street_word_as_common_noun_not_address(self):
        self.assertNotIn("ADDRESS", types_in("Шоссе было пустым совсем"))
        self.assertNotIn("ADDRESS", types_in("На площади собрались люди"))


class RecallRegressions(unittest.TestCase):
    """Бывшие пропуски — теперь должны ловиться."""

    def test_compressed_ipv6(self):
        for addr in (
            "server at 2001:db8::8a2e:370:7334 down",
            "node 2001:db8:85a3::8a2e:370:7334 ok",
            "link fe80::1ff:fe23:4567:890a up",
        ):
            self.assertIn("IP", types_in(addr), addr)

    def test_github_fine_grained_pat(self):
        token = "github_pat_" + "1" * 82
        self.assertIn("GITHUB_TOKEN", types_in(f"token {token}"))

    def test_dotted_card(self):
        self.assertIn("CREDIT_CARD", types_in("card 4111.1111.1111.1111"))

    def test_dotted_snils(self):
        self.assertIn("SNILS", types_in("СНИЛС 112.233.445.95"))

    def test_dotted_ru_phone(self):
        self.assertIn("PHONE_RU", types_in("тел 8.916.123.45.67"))

    def test_cisco_mac(self):
        self.assertIn("MAC", types_in("device 001A.2B3C.4D5E online"))

    def test_more_secret_prefixes(self):
        cases = {
            "GITLAB_TOKEN": "glpat-" + "a" * 20,
            "HF_TOKEN": "hf_" + "A" * 34,
            "NPM_TOKEN": "npm_" + "a" * 36,
            "GOOGLE_OAUTH_SECRET": "GOCSPX-" + "b" * 28,
            "DO_TOKEN": "dop_v1_" + "a" * 64,
            "SHOPIFY_TOKEN": "shpat_" + "a" * 32,
            "SQUARE_TOKEN": "sq0atp-" + "c" * 22,
            "SENDGRID_KEY": "SG." + "a" * 22 + "." + "b" * 43,
        }
        for expected_type, value in cases.items():
            self.assertIn(expected_type, types_in(f"secret {value} end"), expected_type)


class ReDoSRegressions(unittest.TestCase):
    """Латентные ReDoS, найденные адверсариал-аудитом и исправленные."""

    def test_email_dotted_input_fast(self):
        # Точечный вход (a.a.a...) раньше давал O(n^2) в email-регулярке.
        import time

        text = "a." * 20000  # 40 КБ
        t0 = time.perf_counter()
        scan(text)
        self.assertLess(time.perf_counter() - t0, 0.5)

    def test_url_credentials_long_letters_fast(self):
        import time

        text = "x" * 50000
        t0 = time.perf_counter()
        scan(text)
        self.assertLess(time.perf_counter() - t0, 0.5)


class PseudonymLeakRegressions(unittest.TestCase):
    """Псевдоним секрета НЕ должен сохранять буквы оригинала (утечка)."""

    def test_pseudonym_secret_no_letter_leak(self):
        from datashield import redact

        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = redact("key " + secret, strategy="pseudonym").masked_text
        fake = masked.split("key ", 1)[1]
        self.assertEqual(len(fake), len(secret))   # длина сохранена
        self.assertNotEqual(fake, secret)
        # буквенный костяк оригинала не утёк
        orig_letters = "".join(c for c in secret if c.isalpha())
        self.assertNotIn(orig_letters, fake)

    def test_pseudonym_card_still_format_preserving(self):
        from datashield import redact
        from datashield.validators import luhn_check

        masked = redact("card 4111 1111 1111 1111", strategy="pseudonym").masked_text
        digits = "".join(c for c in masked if c.isdigit())
        self.assertTrue(luhn_check(digits))  # фейк-карта валидна по Луну


class FalsePositiveSuppressionTests(unittest.TestCase):
    """Подавление FP, найденных адверсариал-аудитом Блока F."""

    def test_version_not_ip(self):
        self.assertNotIn("IP", types_in("версия сборки 1.2.3.4 финальная"))
        self.assertNotIn("IP", types_in("Build 2.10.4 ready"))

    def test_long_oid_not_ip(self):
        self.assertNotIn("IP", types_in("oid 2.5.29.17.1 cert"))

    def test_real_ip_still_detected(self):
        self.assertIn("IP", types_in("DNS 8.8.8.8 google"))
        self.assertIn("IP", types_in("сервер 192.168.0.1 в сети"))

    def test_uuid_not_aadhaar(self):
        self.assertNotIn(
            "AADHAAR", types_in("id 550e8400-e29b-41d4-a716-121212121212")
        )

    def test_order_number_not_card(self):
        # 16-значный номер заказа на Луна, но IIN не 2-6.
        self.assertNotIn("CREDIT_CARD", types_in("заказ 1234567812345670 готов"))


class KeywordGatedStillWork(unittest.TestCase):
    """SSN/NINO ловятся при ключевом слове рядом."""

    def test_ssn_with_keyword(self):
        self.assertIn("US_SSN", types_in("SSN: 123-45-6789"))
        self.assertIn("US_SSN", types_in("social security 123-45-6789"))

    def test_nino_with_keyword(self):
        self.assertIn("UK_NINO", types_in("NINO AB123456C"))


class NoRegressionOnGoodCases(unittest.TestCase):
    """Контроль: то, что должно ловиться, по-прежнему ловится."""

    def test_real_names_still_detected(self):
        self.assertIn("PERSON", types_in("John Smith called"))
        self.assertIn("PERSON", types_in("Иван Петров пришёл"))

    def test_real_address_still_detected(self):
        self.assertIn("ADDRESS", types_in("ул. Ленина дом 5"))
        self.assertIn("ADDRESS", types_in("шоссе Энтузиастов 12"))

    def test_real_card_still_detected(self):
        self.assertIn("CREDIT_CARD", types_in("карта 4111 1111 1111 1111"))

    def test_eth_not_partial_card(self):
        addr = "0x52908400098527886E0F7030069857D2E4169EE7"
        found = types_in(f"wallet {addr}")
        self.assertIn("ETH_ADDRESS", found)
        self.assertNotIn("CREDIT_CARD", found)


if __name__ == "__main__":
    unittest.main()
