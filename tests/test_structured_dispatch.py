"""Тесты диспетчера форматов datashield.structured.redact_format / FORMATS.

Проверяют РЕАЛЬНОЕ поведение Block M:
- FORMATS содержит ровно ключи json-data / ndjson / csv / xml и сопоставлен
  с правильными функциями (redact_json / redact_ndjson / redact_csv / redact_xml);
- каждый ключ FORMATS через redact_format даёт ТОЧНО тот же результат, что и
  прямой вызов соответствующей функции;
- неизвестный fmt → ValueError с понятным сообщением (упоминает формат и список
  доступных);
- кастомный engine действительно прокидывается (ограниченный движок меняет вывод);
- кастомный sensitive_key_re прокидывается во все форматы.

Детерминированно, только stdlib unittest. Продакшен-код не трогаем.
"""
from __future__ import annotations

import re
import unittest

from datashield.api import build_engine
from datashield.structured import (
    FORMATS,
    redact_csv,
    redact_format,
    redact_json,
    redact_ndjson,
    redact_xml,
)

_REDACTED = "[REDACTED]"

# Фикстуры по форматам: имя формата → (исходный текст, прямая функция).
_JSON_SRC = '{"email": "alice@example.com", "n": 1}'
_NDJSON_SRC = '{"email": "alice@example.com"}\n\nне json объект'
_CSV_SRC = "name,email\nBob,alice@example.com\n"
_XML_SRC = "<r><email>alice@example.com</email><password>hunter2</password></r>"

_FIXTURES = {
    "json-data": (_JSON_SRC, redact_json),
    "ndjson": (_NDJSON_SRC, redact_ndjson),
    "csv": (_CSV_SRC, redact_csv),
    "xml": (_XML_SRC, redact_xml),
}


class TestFormatsRegistry(unittest.TestCase):
    """FORMATS: точный состав ключей и корректное сопоставление функций."""

    def test_formats_keys_are_exactly_expected(self):
        self.assertEqual(
            set(FORMATS), {"json-data", "ndjson", "csv", "xml"}
        )

    def test_formats_has_exactly_four_entries(self):
        self.assertEqual(len(FORMATS), 4)

    def test_formats_maps_each_key_to_correct_function(self):
        self.assertIs(FORMATS["json-data"], redact_json)
        self.assertIs(FORMATS["ndjson"], redact_ndjson)
        self.assertIs(FORMATS["csv"], redact_csv)
        self.assertIs(FORMATS["xml"], redact_xml)


class TestDispatchEqualsDirectCall(unittest.TestCase):
    """redact_format(fmt) == прямой вызов соответствующей функции (тот же engine)."""

    def test_each_format_matches_direct_call(self):
        # Один общий движок, чтобы плейсхолдеры/счётчики совпадали детерминированно.
        for fmt, (src, func) in _FIXTURES.items():
            with self.subTest(fmt=fmt):
                eng = build_engine()
                via_dispatch = redact_format(src, fmt, eng)
                eng_direct = build_engine()
                direct = func(src, eng_direct)
                self.assertEqual(via_dispatch, direct)

    def test_json_dispatch_uses_redact_json_default_indent(self):
        # redact_json по умолчанию indent=2 → многострочный вывод; диспетчер
        # прокидывает только engine позиционно, поэтому дефолт сохраняется.
        out = redact_format(_JSON_SRC, "json-data")
        self.assertIn("\n", out)
        self.assertEqual(out, redact_json(_JSON_SRC))

    def test_json_dispatch_redacts_email_via_engine(self):
        out = redact_format(_JSON_SRC, "json-data")
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("alice@example.com", out)

    def test_csv_dispatch_redacts_cell(self):
        out = redact_format(_CSV_SRC, "csv")
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("alice@example.com", out)

    def test_ndjson_dispatch_keeps_blank_and_masks_invalid_line(self):
        out = redact_format(_NDJSON_SRC, "ndjson")
        lines = out.split("\n")
        # Структура из трёх строк сохранена; пустая строка осталась пустой.
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], "")
        # Сырой email не утекает даже из невалидной JSON-строки.
        self.assertNotIn("alice@example.com", out)

    def test_xml_dispatch_redacts_text_and_sensitive_tag(self):
        out = redact_format(_XML_SRC, "xml")
        self.assertIn("[EMAIL_1]", out)
        # Значение под чувствительным тегом <password> → ровно [REDACTED].
        self.assertIn(_REDACTED, out)
        self.assertNotIn("hunter2", out)


class TestUnknownFormat(unittest.TestCase):
    """Неизвестный fmt → ValueError с понятным сообщением."""

    def test_unknown_format_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_format("{}", "bogus")

    def test_unknown_format_message_mentions_format_name(self):
        with self.assertRaises(ValueError) as ctx:
            redact_format("{}", "yaml")
        msg = str(ctx.exception)
        self.assertIn("yaml", msg)

    def test_unknown_format_message_lists_available_formats(self):
        with self.assertRaises(ValueError) as ctx:
            redact_format("{}", "")
        msg = str(ctx.exception)
        for known in ("json-data", "ndjson", "csv", "xml"):
            self.assertIn(known, msg)

    def test_known_format_with_wrong_case_is_unknown(self):
        # Ключи FORMATS чувствительны к регистру; "JSON-DATA" не существует.
        with self.assertRaises(ValueError):
            redact_format("{}", "JSON-DATA")


class TestCustomEngineThreaded(unittest.TestCase):
    """Кастомный engine реально прокидывается в выбранную функцию формата."""

    def test_restricted_engine_changes_output(self):
        # Движок, ограниченный только телефонами РФ, не должен трогать email.
        eng_phone = build_engine(only=["PHONE_RU"])
        restricted = redact_format(_JSON_SRC, "json-data", eng_phone)
        default = redact_format(_JSON_SRC, "json-data", build_engine())
        self.assertNotEqual(restricted, default)
        # email остаётся нетронутым именно из-за переданного движка.
        self.assertIn("alice@example.com", restricted)

    def test_restricted_engine_matches_direct_call(self):
        eng_phone = build_engine(only=["PHONE_RU"])
        via_dispatch = redact_format(_JSON_SRC, "json-data", eng_phone)
        direct = redact_json(_JSON_SRC, eng_phone)
        self.assertEqual(via_dispatch, direct)


class TestCustomSensitiveKeyReThreaded(unittest.TestCase):
    """Кастомный sensitive_key_re прокидывается во все форматы."""

    def test_custom_key_re_json(self):
        custom = re.compile("nickname")
        out = redact_format(
            '{"nickname": "bob"}', "json-data", None, sensitive_key_re=custom
        )
        self.assertIn(_REDACTED, out)
        self.assertNotIn("bob", out)
        # И совпадает с прямым вызовом с тем же паттерном.
        self.assertEqual(
            out, redact_json('{"nickname": "bob"}', None, sensitive_key_re=custom)
        )

    def test_custom_key_re_csv(self):
        custom = re.compile("nickname")
        src = "nickname,city\nbob,paris\n"
        out = redact_format(src, "csv", None, sensitive_key_re=custom)
        self.assertEqual(out, redact_csv(src, None, sensitive_key_re=custom))
        self.assertIn(_REDACTED, out)
        self.assertNotIn("bob", out)

    def test_custom_key_re_ndjson(self):
        custom = re.compile("nickname")
        src = '{"nickname": "bob"}'
        out = redact_format(src, "ndjson", None, sensitive_key_re=custom)
        self.assertEqual(out, redact_ndjson(src, None, sensitive_key_re=custom))
        self.assertIn(_REDACTED, out)
        self.assertNotIn("bob", out)

    def test_custom_key_re_xml(self):
        custom = re.compile("nickname")
        src = "<r><nickname>bob</nickname></r>"
        out = redact_format(src, "xml", None, sensitive_key_re=custom)
        self.assertEqual(out, redact_xml(src, None, sensitive_key_re=custom))
        self.assertIn(_REDACTED, out)
        self.assertNotIn("bob", out)


class TestPublicReExport(unittest.TestCase):
    """Block M API реэкспортирован из верхнеуровневого пакета datashield —
    не только из datashield.structured (раньше были только json/csv)."""

    def test_top_level_package_exports_block_m_api(self):
        import datashield

        for name in ("redact_ndjson", "redact_xml", "redact_format"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(datashield, name), name)
                self.assertIn(name, datashield.__all__)

    def test_reexport_is_the_same_object(self):
        import datashield

        self.assertIs(datashield.redact_ndjson, redact_ndjson)
        self.assertIs(datashield.redact_xml, redact_xml)
        self.assertIs(datashield.redact_format, redact_format)


if __name__ == "__main__":
    unittest.main()
