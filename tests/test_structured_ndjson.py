"""Тесты для datashield.structured.redact_ndjson (NDJSON / JSON Lines).

Проверяют РЕАЛЬНОЕ поведение построчной маскировки:
- каждая непустая строка — отдельный JSON-объект (json.loads → redact_object → dumps);
- строковые значения прогоняются через движок (email/phone → типизированный плейсхолдер);
- значение под «чувствительным» ключом (password/token) → ровно "[REDACTED]";
- пустые и пробельные строки сохраняются как есть; число строк не меняется;
- невалидная JSON-строка маскируется как обычный текст — сырьё/PII не утекает;
- вложенные объекты/массивы обрабатываются рекурсивно;
- не-ASCII (кириллица/китайский) сохраняется без искажений (ensure_ascii=False);
- числа/булевы/null не трогаются;
- идемпотентность: повторный прогон не ломает результат;
- один объект → одна строка вывода (без переводов строки внутри объекта).

Один движок собирается через build_engine() и переиспользуется. Детерминировано:
без рандома и времени. Продакшен-код не модифицируется.
"""
from __future__ import annotations

import json
import unittest

from datashield.api import build_engine
from datashield.structured import redact_ndjson


class NdjsonBasicTest(unittest.TestCase):
    """Базовая построчная маскировка и формат вывода."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_email_masked_per_line(self) -> None:
        out = redact_ndjson('{"email": "a@b.com", "name": "Bob"}', self.eng)
        obj = json.loads(out)
        self.assertEqual(obj["email"], "[EMAIL_1]")
        self.assertEqual(obj["name"], "Bob")

    def test_phone_masked(self) -> None:
        out = redact_ndjson('{"phone": "+7 999 123-45-67"}', self.eng)
        self.assertEqual(json.loads(out)["phone"], "[PHONE_RU_1]")

    def test_each_line_is_independent_object(self) -> None:
        text = '{"email": "a@b.com"}\n{"phone": "+7 999 123-45-67"}'
        out = redact_ndjson(text, self.eng)
        lines = out.split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["email"], "[EMAIL_1]")
        self.assertEqual(json.loads(lines[1])["phone"], "[PHONE_RU_1]")

    def test_default_engine_when_none(self) -> None:
        # engine=None → build_engine() внутри; результат идентичен явному движку.
        out = redact_ndjson('{"email": "a@b.com"}')
        self.assertEqual(json.loads(out)["email"], "[EMAIL_1]")

    def test_one_object_one_output_line(self) -> None:
        # Компактность: ни в одном выходном объекте нет внутренних переводов строки.
        text = '{"a": 1}\n{"b": 2}\n{"c": 3}'
        out = redact_ndjson(text, self.eng)
        self.assertEqual(len(out.split("\n")), 3)
        for line in out.split("\n"):
            self.assertNotIn("\n", line)
            json.loads(line)  # каждая строка — валидный самостоятельный JSON


class NdjsonSensitiveKeyTest(unittest.TestCase):
    """Чувствительные ключи маскируются целиком значением [REDACTED]."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_password_and_token_redacted(self) -> None:
        text = '{"password": "hunter2", "token": "abc123", "user": "joe"}'
        obj = json.loads(redact_ndjson(text, self.eng))
        self.assertEqual(obj["password"], "[REDACTED]")
        self.assertEqual(obj["token"], "[REDACTED]")
        self.assertEqual(obj["user"], "joe")

    def test_sensitive_value_not_leaked(self) -> None:
        out = redact_ndjson('{"password": "hunter2"}', self.eng)
        self.assertNotIn("hunter2", out)

    def test_sensitive_key_in_nested_object(self) -> None:
        text = '{"creds": {"api_key": "SECRETKEY", "ok": "plain"}}'
        obj = json.loads(redact_ndjson(text, self.eng))
        self.assertEqual(obj["creds"]["api_key"], "[REDACTED]")
        self.assertEqual(obj["creds"]["ok"], "plain")
        self.assertNotIn("SECRETKEY", redact_ndjson(text, self.eng))


class NdjsonEmptyLinesTest(unittest.TestCase):
    """Пустые и пробельные строки сохраняются как есть; счёт строк стабилен."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_blank_line_between_objects_preserved(self) -> None:
        text = '{"a": "x@y.com"}\n\n{"b": 1}'
        out = redact_ndjson(text, self.eng)
        lines = out.split("\n")
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], "")
        self.assertEqual(json.loads(lines[0])["a"], "[EMAIL_1]")
        self.assertEqual(json.loads(lines[2])["b"], 1)

    def test_trailing_newline_preserved(self) -> None:
        # split("\n") по входу с финальным \n даёт хвостовую пустую строку.
        out = redact_ndjson('{"a": "x@y.com"}\n', self.eng)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.split("\n")[-1], "")

    def test_whitespace_only_line_preserved_verbatim(self) -> None:
        text = '{"a": 1}\n   \n{"b": 2}'
        out = redact_ndjson(text, self.eng)
        self.assertEqual(out.split("\n")[1], "   ")

    def test_empty_input_returns_empty(self) -> None:
        self.assertEqual(redact_ndjson("", self.eng), "")


class NdjsonInvalidLineTest(unittest.TestCase):
    """Невалидная JSON-строка маскируется как текст; PII/сырьё не утекает."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_invalid_line_masked_as_text(self) -> None:
        text = "not json a@b.com here\n{\"ok\": 1}"
        out = redact_ndjson(text, self.eng)
        lines = out.split("\n")
        # Первая строка — не JSON, но email в ней замаскирован как обычный текст.
        self.assertIn("[EMAIL_1]", lines[0])
        self.assertNotIn("a@b.com", lines[0])
        # Вторая строка — валидный JSON, обработана штатно.
        self.assertEqual(json.loads(lines[1])["ok"], 1)

    def test_invalid_line_does_not_leak_pii(self) -> None:
        # «Похоже на JSON», но сломано: значения с PII не должны вытечь сырыми.
        text = '{bad json password=hunter2 and email john@example.com'
        out = redact_ndjson(text, self.eng)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("john@example.com", out)
        self.assertIn("[EMAIL_1]", out)

    def test_invalid_line_count_unchanged(self) -> None:
        text = "garbage one a@b.com\nalso broken {"
        out = redact_ndjson(text, self.eng)
        self.assertEqual(len(out.split("\n")), 2)


class NdjsonNestedTest(unittest.TestCase):
    """Вложенные объекты и массивы обрабатываются рекурсивно."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_nested_objects_and_arrays(self) -> None:
        text = (
            '{"user": {"email": "x@y.com", "deep": {"password": "p"}}, '
            '"list": ["a@b.com", 1, null]}'
        )
        obj = json.loads(redact_ndjson(text, self.eng))
        self.assertEqual(obj["user"]["email"], "[EMAIL_1]")
        self.assertEqual(obj["user"]["deep"]["password"], "[REDACTED]")
        self.assertEqual(obj["list"][0], "[EMAIL_1]")
        self.assertEqual(obj["list"][1], 1)
        self.assertIsNone(obj["list"][2])

    def test_top_level_array_line(self) -> None:
        obj = json.loads(redact_ndjson('["a@b.com", 1, true]', self.eng))
        self.assertEqual(obj[0], "[EMAIL_1]")
        self.assertEqual(obj[1], 1)
        self.assertIs(obj[2], True)


class NdjsonNonAsciiTest(unittest.TestCase):
    """Не-ASCII текст (кириллица/китайский) сохраняется без искажений."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_cyrillic_and_chinese_preserved(self) -> None:
        text = '{"имя": "Алиса", "city": "北京"}'
        out = redact_ndjson(text, self.eng)
        obj = json.loads(out)
        self.assertEqual(obj["имя"], "Алиса")
        self.assertEqual(obj["city"], "北京")
        # ensure_ascii=False: не-ASCII печатается как символы, без \uXXXX-эскейпа.
        self.assertIn("Алиса", out)
        self.assertIn("北京", out)
        self.assertNotIn("\\u", out)

    def test_cyrillic_email_in_value_masked_when_detected(self) -> None:
        # Латинский email рядом с кириллицей: PII маскируется, текст вокруг цел.
        text = '{"note": "пиши на a@b.com спасибо"}'
        obj = json.loads(redact_ndjson(text, self.eng))
        self.assertIn("[EMAIL_1]", obj["note"])
        self.assertIn("спасибо", obj["note"])
        self.assertNotIn("a@b.com", obj["note"])


class NdjsonScalarsTest(unittest.TestCase):
    """Числа, булевы и null не трогаются."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_numbers_bools_null_untouched(self) -> None:
        text = '{"n": 42, "f": 3.14, "t": true, "fa": false, "z": null}'
        obj = json.loads(redact_ndjson(text, self.eng))
        self.assertEqual(obj["n"], 42)
        self.assertEqual(obj["f"], 3.14)
        self.assertIs(obj["t"], True)
        self.assertIs(obj["fa"], False)
        self.assertIsNone(obj["z"])

    def test_numeric_value_under_sensitive_key_redacted(self) -> None:
        # Под чувствительным ключом маскируется даже нестроковый скаляр.
        obj = json.loads(redact_ndjson('{"pin": 1234}', self.eng))
        self.assertEqual(obj["pin"], "[REDACTED]")


class NdjsonIdempotencyTest(unittest.TestCase):
    """Повторный прогон не ломает уже замаскированный вывод."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.eng = build_engine()

    def test_double_pass_is_stable(self) -> None:
        text = (
            '{"email": "a@b.com", "password": "x"}\n'
            "\n"
            '{"phone": "+7 999 123-45-67", "n": 7}'
        )
        once = redact_ndjson(text, self.eng)
        twice = redact_ndjson(once, self.eng)
        self.assertEqual(once, twice)

    def test_placeholders_survive_second_pass(self) -> None:
        once = redact_ndjson('{"email": "a@b.com", "token": "t"}', self.eng)
        twice = redact_ndjson(once, self.eng)
        obj = json.loads(twice)
        self.assertEqual(obj["email"], "[EMAIL_1]")
        self.assertEqual(obj["token"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
