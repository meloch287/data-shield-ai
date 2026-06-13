"""Генеративные тесты: строим валидные значения по контрольным суммам и проверяем
детекцию; портим контрольную цифру — проверяем отсутствие детекции."""
import unittest

from datashield import scan
from datashield.validators import luhn_check, validate_inn
from datashield.validators_intl import verhoeff_check


def types(text):
    return {f.type for f in scan(text)}


def make_card(prefix):
    body = prefix + "0" * (15 - len(prefix))
    for d in range(10):
        if luhn_check(body + str(d)):
            return body + str(d)
    raise AssertionError


def make_inn10(base9):
    coeffs = (2, 4, 10, 3, 5, 9, 4, 6, 8)
    c = sum(int(base9[i]) * coeffs[i] for i in range(9)) % 11 % 10
    return base9 + str(c)


def make_aadhaar(base11):
    for d in range(10):
        if verhoeff_check(base11 + str(d)):
            return base11 + str(d)
    raise AssertionError


class GeneratedValidDetected(unittest.TestCase):
    def test_many_valid_cards_detected(self):
        for prefix in ("4", "51", "53", "2221", "6011", "34"):
            card = make_card(prefix)
            self.assertTrue(luhn_check(card))
            self.assertIn("CREDIT_CARD", types(f"карта {card}"), card)

    def test_valid_inn_detected_with_keyword(self):
        for base in ("770708389", "583622845", "123456789"):
            inn = make_inn10(base)
            self.assertTrue(validate_inn(inn))
            self.assertIn("INN", types(f"ИНН {inn}"), inn)

    def test_valid_aadhaar_detected(self):
        for base in ("23412341234", "98765432109", "55512345678"):
            a = make_aadhaar(base)
            self.assertIn("AADHAAR", types(f"Aadhaar {a}"), a)


class GeneratedInvalidRejected(unittest.TestCase):
    def test_bad_luhn_not_card(self):
        for prefix in ("4", "51", "6011"):
            card = make_card(prefix)
            bad = card[:-1] + str((int(card[-1]) + 1) % 10)
            self.assertFalse(luhn_check(bad))
            self.assertNotIn("CREDIT_CARD", types(f"карта {bad}"), bad)

    def test_bad_inn_not_detected(self):
        inn = make_inn10("770708389")
        bad = inn[:-1] + str((int(inn[-1]) + 1) % 10)
        self.assertNotIn("INN", types(f"ИНН {bad}"))


class GeneratedSecretsDetected(unittest.TestCase):
    """Секреты строим в рантайме (конкатенацией), чтобы не попасть в push-protection."""

    def test_prefixed_tokens(self):
        cases = {
            "AWS_ACCESS_KEY": "AKIA" + "A" * 16,
            "GITHUB_TOKEN": "ghp_" + "A" * 36,
            "GITHUB_TOKEN_pat": "github_pat_" + "1" * 82,
            "GITLAB_TOKEN": "glpat-" + "a" * 20,
            "TWILIO_SID": "AC" + "a" * 32,
            "TELEGRAM_BOT_TOKEN": "123456789:" + "A" * 35,
        }
        for label, value in cases.items():
            expected = label.split("_pat")[0]
            self.assertIn(expected, types(f"secret {value} end"), label)


if __name__ == "__main__":
    unittest.main()
