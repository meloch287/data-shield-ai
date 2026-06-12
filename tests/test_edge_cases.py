"""Краевые случаи движка/редакции и идемпотентность.

Покрываем граничные ситуации, которые легко сломать при рефакторинге:
пустой ввод, текст без данных, юникод/эмодзи рядом с данными, дедупликацию
одинаковых значений в один плейсхолдер, нумерацию разных значений, позиции
в начале/конце/середине, многострочный текст, перекрывающиеся кандидаты
(телефон РФ vs international) и идемпотентность redact(redact(text)).
"""
import unittest

from datashield import Config, redact, scan
from datashield.detectors.base import Finding
from datashield.engine import RedactionEngine, resolve_overlaps


class EmptyAndBlankTests(unittest.TestCase):
    """Пустая строка, только пробелы, текст без конфиденциальных данных."""

    def test_empty_string(self):
        result = redact("")
        self.assertEqual(result.masked_text, "")
        self.assertEqual(result.stats, {})
        self.assertEqual(result.findings, [])
        self.assertEqual(result.placeholders, {})
        self.assertEqual(result.original_length, 0)

    def test_scan_empty_string(self):
        self.assertEqual(scan(""), [])

    def test_only_spaces(self):
        text = "     "
        result = redact(text)
        # Пробелы не данные: текст возвращается как есть.
        self.assertEqual(result.masked_text, text)
        self.assertEqual(result.stats, {})

    def test_only_whitespace_mixed(self):
        text = "  \t \n  \r\n "
        result = redact(text)
        self.assertEqual(result.masked_text, text)
        self.assertEqual(result.findings, [])

    def test_plain_text_no_data(self):
        text = "Просто обычный текст без всяких персональных данных."
        result = redact(text)
        self.assertEqual(result.masked_text, text)
        self.assertEqual(result.stats, {})

    def test_plain_text_with_digits_but_no_pii(self):
        # Голые числа без формата/ключевого слова не считаются данными.
        text = "Купил 3 яблока и 12 груш за 100 рублей."
        result = redact(text)
        self.assertEqual(result.masked_text, text)
        self.assertEqual(result.findings, [])

    def test_punctuation_only(self):
        text = "!?.,;:—()[]{}<>"
        self.assertEqual(redact(text).masked_text, text)


class PositionEdgeTests(unittest.TestCase):
    """Данные в начале, в конце, единственным содержимым строки."""

    def test_data_at_start(self):
        result = redact("a@b.com — это мой адрес")
        self.assertTrue(result.masked_text.startswith("[EMAIL_1]"))
        self.assertNotIn("a@b.com", result.masked_text)

    def test_data_at_end(self):
        result = redact("напиши на a@b.com")
        self.assertTrue(result.masked_text.endswith("[EMAIL_1]"))
        self.assertNotIn("a@b.com", result.masked_text)

    def test_data_is_whole_string(self):
        result = redact("a@b.com")
        self.assertEqual(result.masked_text, "[EMAIL_1]")

    def test_finding_start_is_zero_when_at_start(self):
        findings = scan("a@b.com потом текст")
        self.assertEqual(findings[0].start, 0)

    def test_finding_end_is_text_length_when_at_end(self):
        text = "адрес a@b.com"
        findings = scan(text)
        self.assertEqual(findings[-1].end, len(text))

    def test_surrounding_text_preserved(self):
        result = redact("до| a@b.com |после")
        self.assertEqual(result.masked_text, "до| [EMAIL_1] |после")


class UnicodeAndEmojiTests(unittest.TestCase):
    """Юникод и эмодзи рядом с данными не должны ломать редакцию."""

    def test_emoji_adjacent_to_email(self):
        result = redact("Привет 👋 пиши на a@b.com 🚀 срочно")
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("👋", result.masked_text)
        self.assertIn("🚀", result.masked_text)
        self.assertNotIn("a@b.com", result.masked_text)

    def test_cyrillic_around_data(self):
        result = redact("Электронная почта: a@b.com — пишите.")
        self.assertEqual(result.masked_text, "Электронная почта: [EMAIL_1] — пишите.")

    def test_emoji_inside_digits_breaks_match(self):
        # Эмодзи разрывает последовательность цифр, поэтому карта не матчится.
        text = "карта 4111🤖1111 1111 1111"
        result = redact(text)
        self.assertEqual(result.masked_text, text)
        self.assertNotIn("[CREDIT_CARD_1]", result.masked_text)

    def test_multibyte_does_not_shift_offsets(self):
        # Несколько эмодзи перед данными: смещения считаются по символам Python,
        # значит маскировка по позициям не должна съедать соседние символы.
        text = "🎉🎊🥳 mail a@b.com end"
        result = redact(text)
        self.assertEqual(result.masked_text, "🎉🎊🥳 mail [EMAIL_1] end")

    def test_unicode_text_no_data(self):
        text = "日本語のテキスト 한국어 텍스트 中文文本"
        self.assertEqual(redact(text).masked_text, text)


class DeduplicationTests(unittest.TestCase):
    """Несколько одинаковых значений -> один плейсхолдер."""

    def test_same_email_thrice_one_placeholder(self):
        result = redact("a@b.com, a@b.com, a@b.com")
        self.assertEqual(result.masked_text, "[EMAIL_1], [EMAIL_1], [EMAIL_1]")
        self.assertNotIn("[EMAIL_2]", result.masked_text)

    def test_same_value_dedup_but_stats_count_each(self):
        # placeholders дедуплицируются, но stats считают каждое вхождение.
        result = redact("a@b.com и опять a@b.com")
        self.assertEqual(result.masked_text.count("[EMAIL_1]"), 2)
        self.assertEqual(result.stats["EMAIL"], 2)
        # В карте плейсхолдеров — единственная запись.
        self.assertEqual(result.placeholders, {"[EMAIL_1]": "EMAIL"})

    def test_findings_count_equals_occurrences(self):
        findings = scan("a@b.com a@b.com a@b.com")
        self.assertEqual(len(findings), 3)

    def test_same_value_across_lines(self):
        result = redact("строка a@b.com\nдругая a@b.com")
        self.assertEqual(result.masked_text.count("[EMAIL_1]"), 2)


class NumberingTests(unittest.TestCase):
    """Разные значения -> разные номера, нумерация по типу."""

    def test_distinct_emails_increment(self):
        result = redact("a@b.com c@d.com e@f.com")
        self.assertEqual(result.masked_text, "[EMAIL_1] [EMAIL_2] [EMAIL_3]")

    def test_numbering_is_per_type_independent(self):
        result = redact("почта a@b.com айпи 8.8.8.8 ещё c@d.com")
        # У EMAIL своя нумерация, у IP — своя; обе начинаются с 1.
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[EMAIL_2]", result.masked_text)
        self.assertIn("[IP_1]", result.masked_text)

    def test_numbering_follows_first_appearance(self):
        # Первое встреченное значение получает _1.
        result = redact("сначала first@x.com потом second@y.com")
        idx1 = result.masked_text.index("[EMAIL_1]")
        idx2 = result.masked_text.index("[EMAIL_2]")
        self.assertLess(idx1, idx2)

    def test_mixed_types_each_own_counter(self):
        result = redact("a@b.com 1.2.3.4 c@d.com 5.6.7.8")
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[EMAIL_2]", result.masked_text)
        self.assertIn("[IP_1]", result.masked_text)
        self.assertIn("[IP_2]", result.masked_text)


class MultilineTests(unittest.TestCase):
    """Многострочный текст: переносы строк сохраняются, данные маскируются."""

    def test_newlines_preserved(self):
        text = "строка1 a@b.com\nстрока2 c@d.com\nстрока3"
        result = redact(text)
        self.assertEqual(
            result.masked_text, "строка1 [EMAIL_1]\nстрока2 [EMAIL_2]\nстрока3"
        )

    def test_data_spanning_multiple_lines_count(self):
        text = "a@b.com\n8.8.8.8\n00:11:22:33:44:55"
        result = redact(text)
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[IP_1]", result.masked_text)
        self.assertIn("[MAC_1]", result.masked_text)
        # Переносы строк на месте.
        self.assertEqual(result.masked_text.count("\n"), 2)

    def test_crlf_preserved(self):
        text = "first a@b.com\r\nsecond c@d.com"
        result = redact(text)
        self.assertIn("\r\n", result.masked_text)
        self.assertEqual(result.masked_text.count("[EMAIL_"), 2)


class LongTextTests(unittest.TestCase):
    """Очень длинный текст: производительность не проверяем, но корректность да."""

    def test_long_text_single_finding(self):
        big = ("слово " * 5000) + "a@b.com" + (" слово" * 5000)
        result = redact(big)
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertEqual(result.stats, {"EMAIL": 1})
        self.assertNotIn("a@b.com", result.masked_text)

    def test_long_text_original_length(self):
        big = "x" * 100000 + " a@b.com"
        result = redact(big)
        self.assertEqual(result.original_length, len(big))

    def test_many_distinct_values(self):
        emails = " ".join(f"user{i}@mail.com" for i in range(50))
        result = redact(emails)
        # 50 различных значений -> номера от 1 до 50.
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[EMAIL_50]", result.masked_text)
        self.assertEqual(result.stats["EMAIL"], 50)

    def test_many_repeats_one_placeholder(self):
        text = " ".join(["same@mail.com"] * 100)
        result = redact(text)
        self.assertEqual(result.masked_text.count("[EMAIL_1]"), 100)
        self.assertNotIn("[EMAIL_2]", result.masked_text)


class OverlappingCandidatesTests(unittest.TestCase):
    """Перекрывающиеся кандидаты: РФ-телефон побеждает международный."""

    def test_ru_phone_beats_intl_with_spaces(self):
        findings = scan("звони +7 909 123 45 67 утром")
        phones = [f for f in findings if f.type.startswith("PHONE")]
        self.assertEqual(len(phones), 1)
        self.assertEqual(phones[0].type, "PHONE_RU")

    def test_ru_phone_beats_intl_no_spaces(self):
        findings = scan("+79091234567")
        phones = [f for f in findings if f.type.startswith("PHONE")]
        self.assertEqual(len(phones), 1)
        self.assertEqual(phones[0].type, "PHONE_RU")

    def test_resolve_overlaps_prefers_higher_confidence(self):
        a = Finding("PHONE_RU", 0, 10, "x", 0.85, "ru")
        b = Finding("PHONE", 0, 10, "x", 0.8, "intl")
        resolved = resolve_overlaps([b, a])
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].type, "PHONE_RU")

    def test_resolve_overlaps_prefers_longer_on_tie(self):
        # При равной уверенности выигрывает более длинный матч.
        short = Finding("A", 0, 4, "abcd", 0.9, "s")
        long = Finding("B", 0, 8, "abcdefgh", 0.9, "l")
        resolved = resolve_overlaps([short, long])
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].type, "B")

    def test_non_overlapping_both_kept(self):
        a = Finding("EMAIL", 0, 5, "x", 0.9, "e")
        b = Finding("IP", 10, 15, "y", 0.9, "i")
        self.assertEqual(len(resolve_overlaps([a, b])), 2)

    def test_adjacent_non_overlapping_kept(self):
        # Соприкасающиеся (end одного == start другого) не пересекаются.
        a = Finding("A", 0, 5, "x", 0.9, "a")
        b = Finding("B", 5, 10, "y", 0.9, "b")
        self.assertEqual(len(resolve_overlaps([a, b])), 2)

    def test_resolve_overlaps_empty(self):
        self.assertEqual(resolve_overlaps([]), [])

    def test_resolve_overlaps_returns_sorted_by_start(self):
        a = Finding("A", 20, 25, "x", 0.9, "a")
        b = Finding("B", 0, 5, "y", 0.9, "b")
        c = Finding("C", 10, 15, "z", 0.9, "c")
        resolved = resolve_overlaps([a, b, c])
        self.assertEqual([f.start for f in resolved], [0, 10, 20])

    def test_findings_returned_in_position_order(self):
        findings = scan("z@z.com потом 192.168.0.1 потом a@b.com")
        starts = [f.start for f in findings]
        self.assertEqual(starts, sorted(starts))


class IdempotencyTests(unittest.TestCase):
    """redact(redact(text)) не должен повторно ломать плейсхолдеры."""

    def test_idempotent_single_email(self):
        once = redact("мой email a@b.com").masked_text
        twice = redact(once).masked_text
        self.assertEqual(once, twice)

    def test_idempotent_multiple_types(self):
        text = "a@b.com 8.8.8.8 +7 909 123 45 67 00:11:22:33:44:55"
        once = redact(text).masked_text
        twice = redact(once).masked_text
        self.assertEqual(once, twice)

    def test_placeholder_not_redetected_as_data(self):
        # Уже выданный плейсхолдер не должен опознаваться как PII.
        result = redact("[EMAIL_1] [IP_1] [PHONE_RU_1]")
        self.assertEqual(result.masked_text, "[EMAIL_1] [IP_1] [PHONE_RU_1]")
        self.assertEqual(result.findings, [])

    def test_idempotent_with_repeats(self):
        text = "a@b.com и снова a@b.com и c@d.com"
        once = redact(text).masked_text
        twice = redact(once).masked_text
        self.assertEqual(once, twice)

    def test_idempotent_multiline(self):
        text = "строка a@b.com\nещё 8.8.8.8\nи карта 4111 1111 1111 1111"
        once = redact(text).masked_text
        twice = redact(once).masked_text
        self.assertEqual(once, twice)

    def test_triple_redact_stable(self):
        text = "контакт a@b.com тел +7 909 123 45 67"
        r1 = redact(text).masked_text
        r2 = redact(r1).masked_text
        r3 = redact(r2).masked_text
        self.assertEqual(r1, r2)
        self.assertEqual(r2, r3)


class CustomTemplateEdgeTests(unittest.TestCase):
    """Краевые случаи с нестандартным шаблоном плейсхолдера."""

    def test_custom_template_applied(self):
        cfg = Config(placeholder_template="<<{type}:{n}>>")
        result = redact("a@b.com", config=cfg)
        self.assertEqual(result.masked_text, "<<EMAIL:1>>")

    def test_custom_template_numbering(self):
        cfg = Config(placeholder_template="#{type}-{n}#")
        result = redact("a@b.com c@d.com", config=cfg)
        self.assertIn("#EMAIL-1#", result.masked_text)
        self.assertIn("#EMAIL-2#", result.masked_text)


class EngineDirectEdgeTests(unittest.TestCase):
    """Прямое обращение к движку на пустом наборе детекторов."""

    def test_engine_no_detectors_passthrough(self):
        engine = RedactionEngine([])
        result = engine.redact("здесь a@b.com но детекторов нет")
        self.assertEqual(result.masked_text, "здесь a@b.com но детекторов нет")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.stats, {})

    def test_engine_no_detectors_empty_text(self):
        engine = RedactionEngine([])
        result = engine.redact("")
        self.assertEqual(result.masked_text, "")
        self.assertEqual(result.original_length, 0)


if __name__ == "__main__":
    unittest.main()
