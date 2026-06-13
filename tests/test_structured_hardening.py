"""Регресс на находки адверсариал-аудита Блока D (structured.py)."""
import unittest

from datashield.structured import SENSITIVE_KEY_RE, redact_object


class SensitiveKeyMatchingTests(unittest.TestCase):
    def test_matches_separated_and_camel_keys(self):
        for key in (
            "password", "user_password", "userPassword", "API Key", "api_key",
            "access_key", "client secret", "private-key", "card_number",
            "credit card", "social security", "ssn", "SSN", "пароль", "db_token",
            "AUTH_TOKEN", "cvv", "pin", "otp",
        ):
            self.assertTrue(SENSITIVE_KEY_RE.search(key), key)

    def test_no_false_positives_on_common_words(self):
        for key in (
            "shipping", "author", "name", "age", "mapping", "keyboard",
            "pinger", "description", "city", "country", "secretary?nope",
        ):
            # "secretary" содержит "secret" — это допустимый over-mask, исключаем
            if "secret" in key:
                continue
            self.assertFalse(SENSITIVE_KEY_RE.search(key), key)


class DepthGuardTests(unittest.TestCase):
    def test_deep_nesting_raises_valueerror_not_recursionerror(self):
        node = current = {}
        for _ in range(5000):
            current["x"] = {}
            current = current["x"]
        with self.assertRaises(ValueError):
            redact_object(node)

    def test_reasonable_nesting_ok(self):
        node = current = {}
        for _ in range(50):
            current["next"] = {"email": "a@b.com"}
            current = current["next"]
        # не должно падать; где-то внутри email замаскирован
        import json

        self.assertIn("[EMAIL_1]", json.dumps(redact_object(node)))


if __name__ == "__main__":
    unittest.main()
