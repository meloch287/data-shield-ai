"""Тесты детекции: позитивные и негативные кейсы (защита от ложных срабатываний)."""
import unittest

from datashield import scan


def types_in(text, **kwargs):
    return {f.type for f in scan(text, **kwargs)}


class InternationalTests(unittest.TestCase):
    def test_email(self):
        self.assertIn("EMAIL", types_in("пиши на john.doe@example.com сегодня"))

    def test_credit_card(self):
        self.assertIn("CREDIT_CARD", types_in("карта 4111 1111 1111 1111"))

    def test_random_16_digits_not_a_card(self):
        # 16-значный номер, НЕ проходящий Луна, не маскируется как карта.
        self.assertNotIn("CREDIT_CARD", types_in("заказ 4111111111111112 готов"))

    def test_iban(self):
        self.assertIn("IBAN", types_in("счёт GB82 WEST 1234 5698 7654 32"))

    def test_ipv4(self):
        self.assertIn("IP", types_in("сервер 192.168.10.50 в сети"))

    def test_ipv6(self):
        self.assertIn("IP", types_in("адрес 2001:0db8:85a3:0000:0000:8a2e:0370:7334"))

    def test_mac(self):
        self.assertIn("MAC", types_in("устройство 00:1A:2B:3C:4D:5E онлайн"))

    def test_time_is_not_ipv6(self):
        self.assertNotIn("IP", types_in("встреча в 12:34:56 по МСК"))

    def test_intl_phone(self):
        self.assertIn("PHONE", types_in("звони +1 415 555 0123 вечером"))


class RussianTests(unittest.TestCase):
    def test_inn_with_keyword(self):
        self.assertIn("INN", types_in("ИНН 7707083893 организации"))

    def test_inn_without_keyword_not_masked(self):
        # 10-значный ИНН без контекста ниже порога — не маскируется.
        self.assertNotIn("INN", types_in("число 7707083893 просто"))

    def test_inn_12_without_keyword(self):
        # 12-значный ИНН имеет 2 контрольные цифры → маскируется и без слова.
        self.assertIn("INN", types_in("идентификатор 500100732259 в базе"))

    def test_snils(self):
        self.assertIn("SNILS", types_in("СНИЛС 112-233-445 95 указан"))

    def test_passport_with_keyword(self):
        self.assertIn("PASSPORT_RU", types_in("паспорт 45 11 123456 выдан"))

    def test_passport_without_keyword_not_masked(self):
        self.assertNotIn("PASSPORT_RU", types_in("код 45 11 123456 в форме"))

    def test_ru_phone(self):
        found = types_in("тел +7 909 123 45 67 рабочий")
        self.assertIn("PHONE_RU", found)


class SecretsTests(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("AWS_ACCESS_KEY", types_in("ключ AKIAIOSFODNN7EXAMPLE здесь"))

    def test_anthropic_key(self):
        self.assertIn(
            "ANTHROPIC_KEY",
            types_in("token sk-ant-api03-AbCdEfGhIj1234567890XyZ_kk"),
        )

    def test_openai_key(self):
        self.assertIn("OPENAI_KEY", types_in("export KEY=sk-abcdefghij1234567890ABCD"))

    def test_github_token(self):
        self.assertIn(
            "GITHUB_TOKEN",
            types_in("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        )

    def test_google_api_key(self):
        self.assertIn(
            "GOOGLE_API_KEY",
            types_in("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
        )

    def test_stripe_key(self):
        # Собираем по частям, чтобы цельный секрето-подобный литерал не попадал
        # ни в исходник, ни в push-protection GitHub. Тело заведомо фейковое.
        key = "sk_" + "live_" + "0000111122223333AAAA"
        self.assertIn("STRIPE_KEY", types_in(f"платёж {key}"))

    def test_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        self.assertIn("JWT", types_in(f"токен {jwt}"))

    def test_private_key_block(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234567890abcdef\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertIn("PRIVATE_KEY", types_in(block))

    def test_password_assignment_masks_only_value(self):
        from datashield import redact

        result = redact("пароль: hunter2secret")
        self.assertIn("PASSWORD", result.stats)
        self.assertIn("пароль:", result.masked_text)
        self.assertNotIn("hunter2secret", result.masked_text)


class OptionalDetectorTests(unittest.TestCase):
    def test_high_entropy_off_by_default(self):
        # high_entropy выключен по умолчанию.
        text = "X9aK2pQ7mZ4wL1nB8vR3cE6tY0uH5jD"
        self.assertNotIn("SECRET", types_in(text))

    def test_high_entropy_enabled_via_config(self):
        from datashield import Config

        cfg = Config(enabled_detectors=("high_entropy",))
        found = {f.type for f in scan("X9aK2pQ7mZ4wL1nB8vR3cE6tY0uH5jD", config=cfg)}
        self.assertIn("SECRET", found)


if __name__ == "__main__":
    unittest.main()
