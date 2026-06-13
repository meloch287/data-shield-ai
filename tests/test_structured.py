"""Тесты для datashield.structured (redact_json / redact_csv / redact_object).

Проверяют РЕАЛЬНОЕ поведение модуля структурной маскировки:
- сохранение структуры вложенных dict/list и нестроковых скаляров (int/bool/null);
- прогон строковых значений через движок детекции;
- значение под «чувствительным» ключом → "[REDACTED]" независимо от типа;
- CSV: маскировка чувствительных колонок целиком + детекция в остальных ячейках,
  сохранение заголовка, корректная обработка ячеек с кавычками/запятыми/переводами;
- redact_object напрямую; невалидный JSON → ValueError (json.loads).

Только stdlib unittest. Один кастомный движок используется в нескольких кейсах.
"""
from __future__ import annotations

import json
import unittest

from datashield import redact_csv, redact_json
from datashield.api import build_engine
from datashield.structured import (
    SENSITIVE_KEY_RE,
    redact_object,
)
from datashield.structured import (
    redact_csv as structured_redact_csv,
)
from datashield.structured import (
    redact_json as structured_redact_json,
)

_REDACTED = "[REDACTED]"


class TestRedactObjectStructure(unittest.TestCase):
    """redact_object: сохранение структуры и нестроковых скаляров."""

    def test_non_string_scalars_preserved(self):
        # int / float / bool / None под несенситивными ключами не трогаются.
        obj = {"age": 30, "ratio": 1.5, "active": True, "off": False, "note": None}
        out = redact_object(obj)
        self.assertEqual(out, {
            "age": 30,
            "ratio": 1.5,
            "active": True,
            "off": False,
            "note": None,
        })
        # Типы сохранены (bool остаётся bool, не строкой).
        self.assertIs(out["active"], True)
        self.assertIs(out["off"], False)
        self.assertIsNone(out["note"])
        self.assertIsInstance(out["age"], int)
        self.assertIsInstance(out["ratio"], float)

    def test_string_value_with_pii_is_redacted_via_engine(self):
        out = redact_object({"email": "alice@example.com"})
        # Строка прогоняется через движок: email → плейсхолдер.
        self.assertEqual(out["email"], "[EMAIL_1]")

    def test_plain_string_without_pii_unchanged(self):
        out = redact_object({"name": "Alice"})
        self.assertEqual(out["name"], "Alice")

    def test_nested_dict_and_list_structure_preserved(self):
        obj = {
            "user": {
                "name": "Alice",
                "email": "alice@example.com",
                "age": 30,
            },
            "items": ["bob@x.com", 7, False, None, "plain"],
        }
        out = redact_object(obj)
        # Структура (вложенность, типы контейнеров, длина списка) сохранена.
        self.assertIsInstance(out, dict)
        self.assertIsInstance(out["user"], dict)
        self.assertIsInstance(out["items"], list)
        self.assertEqual(len(out["items"]), 5)
        self.assertEqual(out["user"]["name"], "Alice")
        self.assertEqual(out["user"]["email"], "[EMAIL_1]")
        self.assertEqual(out["user"]["age"], 30)
        # Список: строка с PII замаскирована, скаляры/строки без PII сохранены.
        self.assertEqual(out["items"][0], "[EMAIL_1]")
        self.assertEqual(out["items"][1], 7)
        self.assertIs(out["items"][2], False)
        self.assertIsNone(out["items"][3])
        self.assertEqual(out["items"][4], "plain")

    def test_top_level_list(self):
        out = redact_object([{"password": "p"}, "plain@mail.com", 5])
        self.assertIsInstance(out, list)
        self.assertEqual(out[0], {"password": _REDACTED})
        self.assertEqual(out[1], "[EMAIL_1]")
        self.assertEqual(out[2], 5)

    def test_does_not_mutate_input(self):
        obj = {"email": "alice@example.com", "n": 1}
        original = json.loads(json.dumps(obj))
        redact_object(obj)
        # Исходный объект не изменён (создаётся новая структура).
        self.assertEqual(obj, original)


class TestSensitiveKeyRedaction(unittest.TestCase):
    """Значение под чувствительным ключом → "[REDACTED]" независимо от типа."""

    def test_sensitive_string_value(self):
        out = redact_object({"password": "hunter2"})
        self.assertEqual(out["password"], _REDACTED)

    def test_sensitive_non_string_scalar_values(self):
        # int / bool / None под чувствительным ключом тоже → [REDACTED].
        out = redact_object({"token": 12345, "pin": True, "secret": None})
        self.assertEqual(out["token"], _REDACTED)
        self.assertEqual(out["pin"], _REDACTED)
        self.assertEqual(out["secret"], _REDACTED)

    def test_api_key_variants(self):
        out = redact_object({"api_key": "k", "api-key": "k", "apikey": "k"})
        self.assertEqual(out["api_key"], _REDACTED)
        self.assertEqual(out["api-key"], _REDACTED)
        self.assertEqual(out["apikey"], _REDACTED)

    def test_ssn_key(self):
        out = redact_object({"ssn": "123-45-6789"})
        self.assertEqual(out["ssn"], _REDACTED)

    def test_case_insensitive_and_russian_keys(self):
        # Регэксп с (?i): регистр не важен; русские ключи поддержаны.
        out = redact_object({"PASSWORD": "x", "Пароль": "тайна", "Токен": "t"})
        self.assertEqual(out["PASSWORD"], _REDACTED)
        self.assertEqual(out["Пароль"], _REDACTED)
        self.assertEqual(out["Токен"], _REDACTED)

    def test_sensitive_regex_directly(self):
        self.assertTrue(SENSITIVE_KEY_RE.search("password"))
        self.assertTrue(SENSITIVE_KEY_RE.search("API_KEY"))
        self.assertTrue(SENSITIVE_KEY_RE.search("пароль"))
        self.assertIsNone(SENSITIVE_KEY_RE.search("username"))
        self.assertIsNone(SENSITIVE_KEY_RE.search("email"))

    def test_sensitive_key_with_container_value_recurses(self):
        # ФАКТ: короткое замыкание [REDACTED] срабатывает только для НЕ-контейнеров.
        # Значение-словарь/список под чувствительным ключом НЕ маскируется целиком;
        # вместо этого рекурсия идёт внутрь (флаг сенситивности не наследуется детьми).
        out = redact_object({
            "auth": {"token": "abc", "x": 1},
            "secret": ["a@b.com", 2],
        })
        self.assertIsInstance(out["auth"], dict)
        # token внутри совпадает по СВОЕМУ ключу → [REDACTED]; x остаётся числом.
        self.assertEqual(out["auth"]["token"], _REDACTED)
        self.assertEqual(out["auth"]["x"], 1)
        # Список под 'secret' обрабатывается поэлементно, целиком НЕ редактится.
        self.assertEqual(out["secret"], ["[EMAIL_1]", 2])


class TestRedactJson(unittest.TestCase):
    """redact_json: JSON-текст → JSON-текст той же структуры."""

    def test_roundtrip_structure_and_scalars(self):
        src = {
            "name": "Alice",
            "email": "alice@example.com",
            "age": 30,
            "active": True,
            "note": None,
            "password": "hunter2",
            "nested": {"token": 12345, "items": ["bob@x.com", 7, False, None]},
        }
        out_text = redact_json(json.dumps(src))
        out = json.loads(out_text)
        self.assertEqual(out, {
            "name": "Alice",
            "email": "[EMAIL_1]",
            "age": 30,
            "active": True,
            "note": None,
            "password": _REDACTED,
            "nested": {
                "token": _REDACTED,
                "items": ["[EMAIL_1]", 7, False, None],
            },
        })

    def test_default_indent_is_two(self):
        # indent по умолчанию = 2 → многострочный вывод с отступом из 2 пробелов.
        out_text = redact_json('{"a": "x", "b": 1}')
        self.assertIn("\n", out_text)
        self.assertIn('\n  "a"', out_text)

    def test_indent_none_compact(self):
        out_text = redact_json('{"a": "alice@example.com", "password": 1}', indent=None)
        # Без отступа — компактная одна строка.
        self.assertNotIn("\n", out_text)
        self.assertEqual(
            json.loads(out_text),
            {"a": "[EMAIL_1]", "password": _REDACTED},
        )

    def test_non_ascii_preserved(self):
        # ensure_ascii=False: кириллица остаётся как есть.
        out_text = redact_json('{"city": "Москва"}')
        self.assertIn("Москва", out_text)

    def test_invalid_json_raises_value_error(self):
        # json.loads на мусоре → JSONDecodeError, подкласс ValueError.
        with self.assertRaises(ValueError):
            redact_json("{not valid json")
        with self.assertRaises(ValueError):
            redact_json("")

    def test_public_import_matches_module(self):
        # from datashield import redact_json — тот же объект, что в модуле.
        self.assertIs(redact_json, structured_redact_json)


class TestRedactCsv(unittest.TestCase):
    """redact_csv: маскировка колонок + детекция, сохранение заголовка/кавычек."""

    def test_header_preserved_and_sensitive_column_redacted(self):
        src = "name,email,password\nAlice,alice@example.com,hunter2\nBob,bob@x.com,s3cret\n"
        out = redact_csv(src)
        lines = out.strip().split("\n")
        # Заголовок сохранён дословно.
        self.assertEqual(lines[0], "name,email,password")
        # email-колонка прошла детекцию; password-колонка целиком [REDACTED].
        self.assertEqual(lines[1], "Alice,[EMAIL_1],[REDACTED]")
        self.assertEqual(lines[2], "Bob,[EMAIL_1],[REDACTED]")

    def test_detection_runs_on_non_sensitive_cells(self):
        # Нет чувствительных колонок → работает только детекция по содержимому.
        src = "a,b\nx,phone +1-202-555-0173\n"
        out = redact_csv(src)
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "a,b")
        # Телефон в ячейке заменён плейсхолдером; структура строки сохранена.
        self.assertTrue(lines[1].startswith("x,"))
        self.assertIn("[PHONE", lines[1])
        self.assertNotIn("202-555-0173", lines[1])

    def test_quoted_cell_with_comma_and_newline(self):
        # Ячейки с запятой и переводом строки внутри кавычек.
        src = 'name,note,password\n"Smith, John","line1\nline2 a@b.com",pw\n'
        out = redact_csv(src)
        # Парсим обратно через csv, чтобы проверить логическую структуру.
        import csv
        import io
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0], ["name", "note", "password"])
        self.assertEqual(len(rows[1]), 3)
        # Запятая внутри имени сохранена как единая ячейка.
        self.assertEqual(rows[1][0], "Smith, John")
        # Перевод строки сохранён, email внутри замаскирован.
        self.assertIn("\n", rows[1][1])
        self.assertIn("[EMAIL_1]", rows[1][1])
        self.assertNotIn("a@b.com", rows[1][1])
        # password-колонка целиком замаскирована.
        self.assertEqual(rows[1][2], _REDACTED)

    def test_empty_input_returned_as_is(self):
        self.assertEqual(redact_csv(""), "")

    def test_sensitive_header_variants(self):
        # token / api_key / пароль как заголовки → колонка целиком [REDACTED].
        src = "token,api_key,пароль,plain\na,b,c,d\n"
        out = redact_csv(src)
        rows = out.strip().split("\n")
        self.assertEqual(rows[0], "token,api_key,пароль,plain")
        self.assertEqual(rows[1], "[REDACTED],[REDACTED],[REDACTED],d")

    def test_public_import_matches_module(self):
        self.assertIs(redact_csv, structured_redact_csv)


class TestCustomEngine(unittest.TestCase):
    """Кастомный движок (build_engine(strategy=...)) в structured-функциях."""

    def test_partial_strategy_in_redact_object(self):
        # partial-стратегия маскирует значение частично, а не плейсхолдером.
        eng = build_engine(strategy="partial")
        out = redact_object({"email": "alice@example.com"}, eng)
        # partial_mask оставляет последние 4 буквенно-цифровых, остальное → '*'.
        self.assertEqual(out["email"], "*****@******e.com")
        # Контрольное значение для сравнения со стандартным движком.
        self.assertNotEqual(out["email"], "[EMAIL_1]")

    def test_sensitive_key_redacted_regardless_of_strategy(self):
        # Под чувствительным ключом значение → [REDACTED] ДО движка,
        # поэтому стратегия движка к нему не применяется.
        eng = build_engine(strategy="partial")
        out = redact_object({"email": "alice@example.com", "password": "topsecret"}, eng)
        self.assertEqual(out["password"], _REDACTED)

    def test_custom_engine_in_redact_json(self):
        eng = build_engine(strategy="partial")
        out_text = redact_json('{"email": "alice@example.com"}', engine=eng)
        out = json.loads(out_text)
        self.assertEqual(out["email"], "*****@******e.com")

    def test_custom_engine_in_redact_csv(self):
        eng = build_engine(strategy="partial")
        src = "email,password\nalice@example.com,pw\n"
        out = redact_csv(src, eng)
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "email,password")
        # Детекция через partial-движок; password-колонка по-прежнему [REDACTED].
        self.assertEqual(lines[1], "*****@******e.com,[REDACTED]")


if __name__ == "__main__":
    unittest.main()
