"""Тесты XML happy-path для datashield.structured.redact_xml (Block M).

Проверяют РЕАЛЬНОЕ поведение маскировки XML (xml.etree.ElementTree):
- текст узлов прогоняется через движок детекции (email/phone → плейсхолдер);
- значения атрибутов прогоняются через движок;
- узлы/атрибуты с чувствительным ИМЕНЕМ (SENSITIVE_KEY_RE по локальному имени,
  без namespace) → целиком "[REDACTED]";
- XML-декларация (<?xml ...?>) сохраняется;
- вложенные элементы, повторяющиеся теги, пустые элементы;
- смешанный контент (text + tail) — оба прогоняются через движок;
- атрибуты с namespace-именами (локальное имя определяет чувствительность);
- комментарии отбрасываются; префиксы namespace нормализуются (ns0:).

Только stdlib unittest. Детерминированно: без рандома/времени.
Сверено с фактическим поведением исходника datashield/structured.py.
"""
from __future__ import annotations

import unittest

from datashield.api import build_engine
from datashield.structured import (
    redact_format,
    redact_xml,
)

_REDACTED = "[REDACTED]"


class TestNodeTextMasking(unittest.TestCase):
    """Текст узлов прогоняется через движок детекции."""

    def test_email_in_node_text_redacted(self):
        out = redact_xml("<user><email>alice@example.com</email></user>")
        self.assertEqual(out, "<user><email>[EMAIL_1]</email></user>")

    def test_phone_in_node_text_redacted(self):
        # +1-номер детектится как обобщённый PHONE, а не PHONE_RU.
        out = redact_xml("<user><phone>+1-202-555-0173</phone></user>")
        self.assertEqual(out, "<user><phone>[PHONE_1]</phone></user>")

    def test_russian_phone_in_node_text_redacted(self):
        out = redact_xml("<user><phone>+7 495 123-45-67</phone></user>")
        self.assertEqual(out, "<user><phone>[PHONE_RU_1]</phone></user>")

    def test_plain_text_without_pii_unchanged(self):
        out = redact_xml("<user><name>Alice</name></user>")
        self.assertEqual(out, "<user><name>Alice</name></user>")

    def test_cyrillic_text_without_pii_preserved(self):
        # ET.tostring(encoding="unicode") сохраняет кириллицу как есть.
        out = redact_xml("<city>Москва</city>")
        self.assertEqual(out, "<city>Москва</city>")


class TestAttributeValueMasking(unittest.TestCase):
    """Значения атрибутов прогоняются через движок."""

    def test_email_attribute_value_redacted(self):
        out = redact_xml('<user email="alice@example.com">hi</user>')
        self.assertEqual(out, '<user email="[EMAIL_1]">hi</user>')

    def test_plain_attribute_value_unchanged(self):
        out = redact_xml('<user role="admin">x</user>')
        self.assertEqual(out, '<user role="admin">x</user>')

    def test_multiple_attributes_mixed(self):
        # Несенситивные имена с PII-значением → детекция; token (имя) → [REDACTED].
        # Самозакрывающийся тег сериализуется с пробелом перед "/>".
        out = redact_xml('<user name="Bob" email="a@b.com" token="xyz"/>')
        self.assertEqual(
            out,
            '<user name="Bob" email="[EMAIL_1]" token="[REDACTED]" />',
        )


class TestSensitiveTagRedaction(unittest.TestCase):
    """Узлы с чувствительным именем → текст целиком [REDACTED]."""

    def test_password_and_token_tags_redacted(self):
        out = redact_xml(
            "<root><password>hunter2</password><token>abc</token></root>"
        )
        self.assertEqual(
            out,
            "<root><password>[REDACTED]</password><token>[REDACTED]</token></root>",
        )

    def test_sensitive_tag_text_redacted_even_without_detected_pii(self):
        # У <secret> нет распознаваемого PII, но имя чувствительное → [REDACTED].
        out = redact_xml("<secret>plain words</secret>")
        self.assertEqual(out, "<secret>[REDACTED]</secret>")

    def test_sensitive_tag_with_only_children_does_not_redact_children(self):
        # ФАКТ: чувствительность тега маскирует ТОЛЬКО собственный текст узла.
        # Если у <secret> нет прямого текста (только дети), дети обрабатываются
        # обычным образом — email внутри <inner> идёт через движок.
        out = redact_xml("<secret><inner>a@b.com</inner></secret>")
        self.assertEqual(out, "<secret><inner>[EMAIL_1]</inner></secret>")

    def test_sensitive_tag_with_text_and_children(self):
        # ФАКТ: прямой текст <secret> ("my a@b.com") → [REDACTED];
        # дети по-прежнему обрабатываются движком отдельно.
        out = redact_xml("<secret>my a@b.com<inner>c@d.com</inner></secret>")
        self.assertEqual(out, "<secret>[REDACTED]<inner>[EMAIL_1]</inner></secret>")


class TestSensitiveAttributeRedaction(unittest.TestCase):
    """Атрибуты с чувствительным именем → значение целиком [REDACTED]."""

    def test_sensitive_attribute_redacted_nonsensitive_kept(self):
        out = redact_xml('<user password="hunter2" name="Alice">x</user>')
        self.assertEqual(out, '<user password="[REDACTED]" name="Alice">x</user>')

    def test_sensitive_attribute_redacted_regardless_of_value_content(self):
        # Значение без PII под чувствительным именем всё равно → [REDACTED].
        out = redact_xml('<creds api_key="plainvalue"/>')
        self.assertEqual(out, '<creds api_key="[REDACTED]" />')


class TestXmlDeclarationPreserved(unittest.TestCase):
    """XML-декларация (<?xml ...?>) сохраняется."""

    def test_simple_declaration_preserved(self):
        out = redact_xml('<?xml version="1.0"?><root><email>a@b.com</email></root>')
        self.assertEqual(
            out,
            '<?xml version="1.0"?>\n<root><email>[EMAIL_1]</email></root>',
        )

    def test_declaration_with_encoding_preserved_verbatim(self):
        out = redact_xml(
            '<?xml version="1.0" encoding="UTF-8"?>\n<r><x>a@b.com</x></r>'
        )
        self.assertEqual(
            out,
            '<?xml version="1.0" encoding="UTF-8"?>\n<r><x>[EMAIL_1]</x></r>',
        )

    def test_no_declaration_no_prolog_added(self):
        out = redact_xml("<r><x>a@b.com</x></r>")
        self.assertEqual(out, "<r><x>[EMAIL_1]</x></r>")
        self.assertNotIn("<?xml", out)


class TestNestedAndRepeatedElements(unittest.TestCase):
    """Вложенные элементы и повторяющиеся теги."""

    def test_deeply_nested_elements(self):
        out = redact_xml("<a><b><c>a@b.com</c></b></a>")
        self.assertEqual(out, "<a><b><c>[EMAIL_1]</c></b></a>")

    def test_repeated_tags_each_masked(self):
        # Плейсхолдеры считаются per-узел (каждый узел — отдельный redact()).
        out = redact_xml("<list><item>a@b.com</item><item>c@d.com</item></list>")
        self.assertEqual(
            out,
            "<list><item>[EMAIL_1]</item><item>[EMAIL_1]</item></list>",
        )

    def test_nested_with_sensitive_child(self):
        out = redact_xml(
            "<account><profile><email>a@b.com</email>"
            "<password>p</password></profile></account>"
        )
        self.assertEqual(
            out,
            "<account><profile><email>[EMAIL_1]</email>"
            "<password>[REDACTED]</password></profile></account>",
        )


class TestEmptyElements(unittest.TestCase):
    """Пустые элементы сериализуются как самозакрывающиеся (с пробелом)."""

    def test_empty_element_self_closing(self):
        out = redact_xml("<root><empty/></root>")
        self.assertEqual(out, "<root><empty /></root>")

    def test_empty_element_with_attribute(self):
        out = redact_xml('<root><node id="1"/></root>')
        self.assertEqual(out, '<root><node id="1" /></root>')

    def test_element_with_no_text_unchanged(self):
        # Узел без текста и без детей остаётся пустым.
        out = redact_xml("<root></root>")
        self.assertEqual(out, "<root />")


class TestMixedContent(unittest.TestCase):
    """Смешанный контент: text узла и tail (хвост после дочернего) — оба через движок."""

    def test_text_and_tail_both_redacted(self):
        # "Contact " — text <p>; "alice@example.com" — text <b>;
        # " now bob@x.com here" — tail <b>, тоже прогоняется движком.
        out = redact_xml(
            "<p>Contact <b>alice@example.com</b> now bob@x.com here</p>"
        )
        self.assertEqual(
            out,
            "<p>Contact <b>[EMAIL_1]</b> now [EMAIL_1] here</p>",
        )

    def test_tail_pii_redacted_after_empty_child(self):
        out = redact_xml("<p>start<br/>tail a@b.com end</p>")
        self.assertEqual(out, "<p>start<br />tail [EMAIL_1] end</p>")

    def test_tail_is_never_treated_as_sensitive(self):
        # ФАКТ: tail всегда идёт через движок (не [REDACTED]), даже если родитель
        # или сам узел носит чувствительное имя — tail к чувствительности не привязан.
        out = redact_xml("<root><token>x</token>plain a@b.com tail</root>")
        self.assertEqual(
            out,
            "<root><token>[REDACTED]</token>plain [EMAIL_1] tail</root>",
        )


class TestNamespaces(unittest.TestCase):
    """Namespace-имена: чувствительность по ЛОКАЛЬНОМУ имени; префиксы нормализуются."""

    def test_default_namespace_prefix_normalized(self):
        # ET перезаписывает default-namespace в ns0:. Текст всё равно маскируется.
        out = redact_xml(
            '<root xmlns="http://example.com/ns"><email>a@b.com</email></root>'
        )
        self.assertEqual(
            out,
            '<ns0:root xmlns:ns0="http://example.com/ns">'
            "<ns0:email>[EMAIL_1]</ns0:email></ns0:root>",
        )

    def test_prefixed_namespace_normalized(self):
        out = redact_xml(
            '<root xmlns:ns="http://e.com"><ns:email>a@b.com</ns:email></root>'
        )
        self.assertEqual(
            out,
            '<root xmlns:ns0="http://e.com">'
            "<ns0:email>[EMAIL_1]</ns0:email></root>",
        )

    def test_sensitive_local_name_in_default_namespace_redacted(self):
        # Локальное имя "password" чувствительно даже под namespace.
        out = redact_xml(
            '<root xmlns="http://e.com"><password>x</password></root>'
        )
        self.assertEqual(
            out,
            '<ns0:root xmlns:ns0="http://e.com">'
            "<ns0:password>[REDACTED]</ns0:password></ns0:root>",
        )

    def test_namespaced_attribute_with_sensitive_local_name_redacted(self):
        # Атрибут s:password — локальное имя "password" → [REDACTED].
        out = redact_xml(
            '<root xmlns:s="http://e.com"><user s:password="secret">x</user></root>'
        )
        self.assertEqual(
            out,
            '<root xmlns:ns0="http://e.com">'
            '<user ns0:password="[REDACTED]">x</user></root>',
        )


class TestCommentsAndDispatch(unittest.TestCase):
    """Комментарии отбрасываются; диспетчер redact_format и публичный импорт."""

    def test_comment_dropped(self):
        out = redact_xml("<root><!-- secret comment --><a>hi</a></root>")
        self.assertEqual(out, "<root><a>hi</a></root>")

    def test_redact_format_dispatches_to_xml(self):
        out = redact_format(
            "<user><email>a@b.com</email></user>", "xml"
        )
        self.assertEqual(out, "<user><email>[EMAIL_1]</email></user>")


class TestCustomEngine(unittest.TestCase):
    """Кастомный движок (build_engine(strategy=...)) применяется к тексту/атрибутам."""

    def test_partial_strategy_on_node_text(self):
        eng = build_engine(strategy="partial")
        out = redact_xml("<user><email>alice@example.com</email></user>", eng)
        # partial оставляет хвост, маскирует остальное '*' — не плейсхолдер.
        self.assertEqual(out, "<user><email>*****@******e.com</email></user>")

    def test_sensitive_tag_redacted_regardless_of_strategy(self):
        # Чувствительный тег → [REDACTED] до движка; стратегия не применяется.
        eng = build_engine(strategy="partial")
        out = redact_xml("<root><password>topsecret</password></root>", eng)
        self.assertEqual(out, "<root><password>[REDACTED]</password></root>")


if __name__ == "__main__":
    unittest.main()
