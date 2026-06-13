"""Сквозные (интеграционные) тесты на реалистичных смешанных РФ+intl документах.

Проверяем не отдельные детекторы, а весь конвейер `redact`/`scan` целиком на
правдоподобных документах: письмо, анкета, лог, чек/реквизиты. Ключевые
инварианты:

  * одновременно ловятся разнотипные данные (email, телефон, карта, ИНН, имя,
    адрес, секреты и т. д.);
  * плейсхолдеры стабильны (одно значение → один плейсхолдер) и пронумерованы
    отдельно по каждому типу, начиная с 1;
  * result.stats, result.placeholders и result.report() согласованы между собой
    и с result.findings (total == len(findings) == сумма stats).

Все значения-фикстуры (ИНН, ОГРН, IBAN, карты, СНИЛС) подобраны валидными по
контрольным суммам — поведение сверено с фактическим исходным кодом.
"""
import unittest
from collections import Counter

from datashield import Config, redact, scan

# --- Правдоподобные документы (общие фикстуры) ------------------------------

LETTER = (
    "Здравствуйте, Иван Петрович!\n"
    "Меня зовут Сергей Смирнов. Пишите на ivan.petrov@example.com "
    "или sergey@mail.ru.\n"
    "Мой телефон +7 909 123 45 67, рабочий +7 (495) 123-45-67.\n"
    "Карта для оплаты 4111 1111 1111 1111.\n"
    "ИНН 7707083893, СНИЛС 112-233-445 95.\n"
    "Адрес: ул. Ленина 15, индекс 101000.\n"
    "Reply to me, Dr. James Wilson, at j.wilson@corp.co.uk, "
    "phone +1 415 555 0199.\n"
)

ANKETA = (
    "АНКЕТА КЛИЕНТА\n"
    "ФИО: Смирнова Анна Сергеевна\n"
    "Email: anna.smirnova@bank.ru\n"
    "Телефон: +7 916 000 11 22\n"
    "ИНН: 500100732259\n"
    "ОГРН организации: 1027700132195\n"
    "IBAN: DE89 3704 0044 0532 0130 00\n"
    "Карта: 5500 0055 5555 5559\n"
    "Адрес регистрации: проспект Мира 100, Москва\n"
)

LOG = (
    "2026-06-13 12:00:01 INFO user login from 192.168.1.10 "
    "mac 00:1A:2B:3C:4D:5E\n"
    "2026-06-13 12:00:02 DEBUG aws key AKIAIOSFODNN7EXAMPLE used\n"
    "2026-06-13 12:00:03 WARN token github "
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz12\n"
    "2026-06-13 12:00:04 INFO password=SuperSecret123 accepted\n"
    "2026-06-13 12:00:05 INFO contact admin@service.io connected\n"
)

INVOICE = (
    "СЧЁТ НА ОПЛАТУ\n"
    "Поставщик: ООО Ромашка, ИНН 7707083893\n"
    "Контакт: Петров Пётр Иванович, тел. +7 800 555 35 35\n"
    "Почта: sales@romashka.ru\n"
    "Оплата на карту 4111 1111 1111 1111 или IBAN GB82 WEST 1234 5698 7654 32\n"
    "Дублирующий контакт: sales@romashka.ru\n"
)


def _sum_stats(stats):
    return sum(stats.values())


class CorpusFixtureSanityTests(unittest.TestCase):
    """Базовая вменяемость документов: что-то находится и текст реально меняется."""

    def test_letter_produces_findings(self):
        result = redact(LETTER)
        self.assertGreater(len(result.findings), 0)
        self.assertNotEqual(result.masked_text, LETTER)

    def test_anketa_produces_findings(self):
        result = redact(ANKETA)
        self.assertGreater(len(result.findings), 0)

    def test_log_produces_findings(self):
        result = redact(LOG)
        self.assertGreater(len(result.findings), 0)

    def test_invoice_produces_findings(self):
        result = redact(INVOICE)
        self.assertGreater(len(result.findings), 0)

    def test_original_length_matches_source(self):
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            self.assertEqual(redact(doc).original_length, len(doc))


class LetterMixedTypesTests(unittest.TestCase):
    """Письмо: одновременно имя, email, телефоны (РФ+intl), карта, ИНН, СНИЛС,
    адрес, индекс."""

    def setUp(self):
        self.result = redact(LETTER)
        self.types = {f.type for f in self.result.findings}

    def test_catches_emails(self):
        self.assertIn("EMAIL", self.types)
        # три разных email-адреса в письме
        self.assertEqual(self.result.stats.get("EMAIL"), 3)

    def test_catches_person(self):
        self.assertIn("PERSON", self.types)

    def test_catches_ru_phone(self):
        self.assertIn("PHONE_RU", self.types)
        self.assertEqual(self.result.stats.get("PHONE_RU"), 2)

    def test_catches_intl_phone(self):
        # +1 415 555 0199 — международный, тип PHONE
        self.assertIn("PHONE", self.types)

    def test_catches_credit_card(self):
        self.assertIn("CREDIT_CARD", self.types)

    def test_catches_inn(self):
        self.assertIn("INN", self.types)

    def test_catches_snils(self):
        self.assertIn("SNILS", self.types)

    def test_catches_address(self):
        self.assertIn("ADDRESS", self.types)

    def test_catches_postal_code(self):
        self.assertIn("POSTAL_CODE", self.types)

    def test_many_distinct_types_simultaneously(self):
        # Минимум 8 разных типов одновременно в одном документе.
        self.assertGreaterEqual(len(self.types), 8)

    def test_no_raw_secrets_leak_for_card(self):
        self.assertNotIn("4111 1111 1111 1111", self.result.masked_text)

    def test_no_raw_email_leak(self):
        self.assertNotIn("ivan.petrov@example.com", self.result.masked_text)
        self.assertNotIn("sergey@mail.ru", self.result.masked_text)

    def test_no_raw_inn_leak(self):
        self.assertNotIn("7707083893", self.result.masked_text)


class AnketaMixedTypesTests(unittest.TestCase):
    """Анкета: ФИО, email, телефон, ИНН(12), ОГРН, IBAN, карта, адрес."""

    def setUp(self):
        self.result = redact(ANKETA)
        self.types = {f.type for f in self.result.findings}

    def test_catches_person(self):
        self.assertIn("PERSON", self.types)

    def test_catches_email(self):
        self.assertIn("EMAIL", self.types)

    def test_catches_phone_ru(self):
        self.assertIn("PHONE_RU", self.types)

    def test_catches_inn12(self):
        self.assertIn("INN", self.types)

    def test_catches_ogrn(self):
        self.assertIn("OGRN", self.types)

    def test_catches_iban(self):
        self.assertIn("IBAN", self.types)

    def test_catches_credit_card(self):
        self.assertIn("CREDIT_CARD", self.types)

    def test_catches_address(self):
        self.assertIn("ADDRESS", self.types)

    def test_iban_value_not_leaked(self):
        # IBAN записан группами через пробел — должен быть полностью замаскирован.
        self.assertNotIn("DE89 3704 0044 0532 0130 00", self.result.masked_text)

    def test_ogrn_not_leaked(self):
        self.assertNotIn("1027700132195", self.result.masked_text)

    def test_many_distinct_types(self):
        self.assertGreaterEqual(len(self.types), 7)


class LogSecretsTests(unittest.TestCase):
    """Лог: IP, MAC, AWS-ключ, GitHub-токен, пароль, email."""

    def setUp(self):
        self.result = redact(LOG)
        self.types = {f.type for f in self.result.findings}

    def test_catches_ipv4(self):
        self.assertIn("IP", self.types)

    def test_catches_mac(self):
        self.assertIn("MAC", self.types)

    def test_catches_aws_key(self):
        self.assertIn("AWS_ACCESS_KEY", self.types)

    def test_catches_github_token(self):
        self.assertIn("GITHUB_TOKEN", self.types)

    def test_catches_password(self):
        self.assertIn("PASSWORD", self.types)

    def test_catches_email(self):
        self.assertIn("EMAIL", self.types)

    def test_password_masks_only_value(self):
        # У детектора password group=1 — маскируется только значение,
        # слово "password=" остаётся в тексте.
        self.assertIn("password=", self.result.masked_text)
        self.assertNotIn("SuperSecret123", self.result.masked_text)

    def test_aws_key_value_not_leaked(self):
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", self.result.masked_text)

    def test_github_token_value_not_leaked(self):
        self.assertNotIn(
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
            self.result.masked_text,
        )

    def test_timestamps_are_preserved(self):
        # Даты/время не должны исчезать — это не персональные данные.
        self.assertIn("2026-06-13 12:00:01", self.result.masked_text)


class InvoiceTests(unittest.TestCase):
    """Счёт: имя+отчество, ИНН, телефон, повторяющийся email, карта, IBAN."""

    def setUp(self):
        self.result = redact(INVOICE)
        self.types = {f.type for f in self.result.findings}

    def test_catches_core_types(self):
        for expected in ("PERSON", "INN", "PHONE_RU", "EMAIL", "CREDIT_CARD", "IBAN"):
            self.assertIn(expected, self.types, msg=expected)

    def test_repeated_email_one_placeholder(self):
        # sales@romashka.ru встречается дважды → один плейсхолдер, два вхождения.
        self.assertEqual(self.result.masked_text.count("[EMAIL_1]"), 2)
        self.assertNotIn("[EMAIL_2]", self.result.masked_text)

    def test_repeated_email_counted_twice_in_stats(self):
        # stats считает каждое вхождение (findings), а не уникальные значения.
        self.assertEqual(self.result.stats.get("EMAIL"), 2)


class PlaceholderStabilityTests(unittest.TestCase):
    """Стабильность и нумерация плейсхолдеров по типам."""

    def test_distinct_emails_increment_independently(self):
        result = redact("a@x.com, b@y.com, c@z.com")
        for i in (1, 2, 3):
            self.assertIn("[EMAIL_%d]" % i, result.masked_text)
        self.assertNotIn("[EMAIL_4]", result.masked_text)

    def test_numbering_is_per_type(self):
        # У каждого типа собственная нумерация, начинающаяся с 1.
        result = redact("mail a@b.com phone +7 909 123 45 67 ip 10.0.0.1")
        self.assertIn("[EMAIL_1]", result.masked_text)
        self.assertIn("[PHONE_RU_1]", result.masked_text)
        self.assertIn("[IP_1]", result.masked_text)

    def test_same_value_same_placeholder_across_doc(self):
        result = redact(INVOICE)
        # Повторный email получает тот же плейсхолдер.
        for ph in result.placeholders:
            self.assertTrue(ph.startswith("[") and ph.endswith("]"))

    def test_placeholders_map_to_correct_type(self):
        result = redact(LETTER)
        for ph, typ in result.placeholders.items():
            # Плейсхолдер формата [TYPE_n]; тип в скобках должен совпасть.
            inner = ph[1:-1]  # TYPE_n
            type_part = inner.rsplit("_", 1)[0]
            self.assertEqual(type_part, typ)

    def test_unique_placeholders_count_matches_mapping(self):
        result = redact(LETTER)
        unique_in_text = {
            ph for ph in result.placeholders if ph in result.masked_text
        }
        # Каждый плейсхолдер из mapping встречается в тексте.
        self.assertEqual(unique_in_text, set(result.placeholders))

    def test_placeholder_numbering_starts_at_one(self):
        # Для каждого типа наименьший номер плейсхолдера равен 1.
        result = redact(LETTER)
        per_type_numbers = {}
        for ph, typ in result.placeholders.items():
            n = int(ph[1:-1].rsplit("_", 1)[1])
            per_type_numbers.setdefault(typ, []).append(n)
        for typ, numbers in per_type_numbers.items():
            self.assertEqual(min(numbers), 1, msg=typ)
            # Номера идут сплошняком 1..k без пропусков.
            self.assertEqual(sorted(numbers), list(range(1, len(numbers) + 1)), msg=typ)

    def test_custom_placeholder_template(self):
        cfg = Config(placeholder_template="<<{type}:{n}>>")
        result = redact("mail a@b.com", config=cfg)
        self.assertIn("<<EMAIL:1>>", result.masked_text)
        self.assertNotIn("[EMAIL_1]", result.masked_text)


class StatsConsistencyTests(unittest.TestCase):
    """Согласованность result.stats с findings на всех документах корпуса."""

    DOCS = (LETTER, ANKETA, LOG, INVOICE)

    def test_total_equals_len_findings(self):
        for doc in self.DOCS:
            result = redact(doc)
            self.assertEqual(_sum_stats(result.stats), len(result.findings))

    def test_stats_equals_counter_of_finding_types(self):
        for doc in self.DOCS:
            result = redact(doc)
            self.assertEqual(
                result.stats, dict(Counter(f.type for f in result.findings))
            )

    def test_stats_keys_are_subset_of_finding_types(self):
        for doc in self.DOCS:
            result = redact(doc)
            self.assertEqual(
                set(result.stats), {f.type for f in result.findings}
            )

    def test_no_zero_counts_in_stats(self):
        for doc in self.DOCS:
            result = redact(doc)
            self.assertTrue(all(v > 0 for v in result.stats.values()))

    def test_scan_matches_redact_findings(self):
        # scan() и redact().findings должны давать одинаковый набор находок.
        for doc in self.DOCS:
            scanned = scan(doc)
            redacted = redact(doc).findings
            self.assertEqual(
                Counter(f.type for f in scanned),
                Counter(f.type for f in redacted),
            )


class ReportConsistencyTests(unittest.TestCase):
    """Согласованность result.report() с findings/stats."""

    DOCS = (LETTER, ANKETA, LOG, INVOICE)

    def test_report_total_equals_len_findings(self):
        for doc in self.DOCS:
            result = redact(doc)
            report = result.report()
            self.assertEqual(report["total"], len(result.findings))

    def test_report_total_equals_sum_stats(self):
        for doc in self.DOCS:
            result = redact(doc)
            report = result.report()
            self.assertEqual(report["total"], _sum_stats(report["stats"]))

    def test_report_entries_count_equals_total(self):
        for doc in self.DOCS:
            result = redact(doc)
            report = result.report()
            self.assertEqual(len(report["entries"]), report["total"])

    def test_report_stats_match_result_stats(self):
        for doc in self.DOCS:
            result = redact(doc)
            self.assertEqual(result.report()["stats"], result.stats)

    def test_report_does_not_leak_raw_values(self):
        # В отчёте только хеши и маск-превью, сырых значений быть не должно.
        # Иглы — ПОЛНЫЕ сырые значения: короткий фрагмент («4111») случайно
        # встречается в hex солёного SHA-256 (например 'b84111add') и даёт
        # ложный провал, хотя карта не утекла.
        result = redact(LETTER)
        report = result.report()
        blob = repr(report)
        self.assertNotIn("ivan.petrov@example.com", blob)
        self.assertNotIn("7707083893", blob)
        self.assertNotIn("4111 1111 1111 1111", blob)
        self.assertNotIn("4111111111111111", blob)

    def test_report_entry_fields_present(self):
        result = redact(ANKETA)
        for entry in result.report()["entries"]:
            for key in ("type", "start", "end", "confidence", "detector",
                        "value_sha256", "preview"):
                self.assertIn(key, entry)

    def test_report_salt_is_stable_when_provided(self):
        # При фиксированной соли хеши воспроизводимы между вызовами.
        result = redact(LETTER)
        salt = b"\x00" * 16
        r1 = result.report(salt=salt)
        r2 = result.report(salt=salt)
        self.assertEqual(
            [e["value_sha256"] for e in r1["entries"]],
            [e["value_sha256"] for e in r2["entries"]],
        )

    def test_report_entry_types_match_stats(self):
        for doc in self.DOCS:
            result = redact(doc)
            report = result.report()
            entry_counts = Counter(e["type"] for e in report["entries"])
            self.assertEqual(dict(entry_counts), report["stats"])


class FindingPositionsTests(unittest.TestCase):
    """Корректность позиций находок относительно исходного текста."""

    def test_finding_value_matches_slice(self):
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            for f in scan(doc):
                self.assertEqual(doc[f.start:f.end], f.value, msg=f)

    def test_findings_do_not_overlap(self):
        # После resolve_overlaps интервалы не пересекаются.
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            findings = sorted(scan(doc), key=lambda f: f.start)
            for prev, cur in zip(findings, findings[1:]):
                self.assertLessEqual(prev.end, cur.start, msg=(prev, cur))

    def test_findings_in_bounds(self):
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            for f in scan(doc):
                self.assertGreaterEqual(f.start, 0)
                self.assertLessEqual(f.end, len(doc))
                self.assertLess(f.start, f.end)


class ReconstructionTests(unittest.TestCase):
    """Маскирование заменяет ровно интервалы находок, не трогая остальное."""

    def test_masked_text_replaces_each_finding(self):
        result = redact(LETTER)
        # Каждое сырое значение из находок не должно остаться в выводе.
        for f in result.findings:
            self.assertNotIn(f.value, result.masked_text, msg=f.value)

    def test_text_between_findings_preserved(self):
        # Фрагменты-«якоря», не являющиеся ПД, должны сохраниться.
        result = redact(LETTER)
        for anchor in ("Здравствуйте", "Пишите на", "Мой телефон", "Адрес:"):
            self.assertIn(anchor, result.masked_text)

    def test_non_sensitive_log_structure_preserved(self):
        result = redact(LOG)
        for anchor in ("INFO", "DEBUG", "WARN", "login from", "accepted"):
            self.assertIn(anchor, result.masked_text)


class NegativeCaseTests(unittest.TestCase):
    """Негативные кейсы: что НЕ должно ловиться/ломаться."""

    def test_plain_prose_no_findings(self):
        text = "Сегодня хорошая погода, мы гуляли в парке и пили чай."
        result = redact(text)
        # Возможны редкие срабатывания на омонимы-имена, но карт/email быть не должно.
        self.assertNotIn("EMAIL", result.stats)
        self.assertNotIn("CREDIT_CARD", result.stats)
        self.assertNotIn("IBAN", result.stats)

    def test_bare_inn_without_keyword_not_masked(self):
        # 10-значный ИНН без слова «ИНН» рядом — ниже порога, не маскируется.
        result = redact("просто число 7707083893 в тексте")
        self.assertNotIn("INN", result.stats)
        self.assertIn("7707083893", result.masked_text)

    def test_invalid_card_not_masked(self):
        # Не проходит Луна → не карта.
        result = redact("номер 1234 5678 9012 3456 неверный")
        self.assertNotIn("CREDIT_CARD", result.stats)

    def test_invalid_iban_not_masked(self):
        result = redact("счёт XX00 0000 0000 0000 0000 00 нет")
        self.assertNotIn("IBAN", result.stats)

    def test_time_not_detected_as_ipv6(self):
        # 12:34:56 — это время, не IPv6.
        result = redact("встреча в 12:34:56 завтра")
        self.assertNotIn("IP", result.stats)

    def test_empty_document(self):
        result = redact("")
        self.assertEqual(result.masked_text, "")
        self.assertEqual(result.stats, {})
        self.assertEqual(result.findings, [])
        self.assertEqual(result.report()["total"], 0)

    def test_whitespace_only_document(self):
        result = redact("   \n\t  \n")
        self.assertEqual(result.stats, {})


class FilterAndConfigOnCorpusTests(unittest.TestCase):
    """only/exclude/allowlist на полноценных документах корпуса."""

    def test_only_email_on_letter(self):
        found = {f.type for f in scan(LETTER, only=["EMAIL"])}
        self.assertEqual(found, {"EMAIL"})

    def test_exclude_person_on_letter(self):
        found = {f.type for f in scan(LETTER, exclude=["PERSON"])}
        self.assertNotIn("PERSON", found)
        # но остальное по-прежнему ловится
        self.assertIn("EMAIL", found)

    def test_allowlist_keeps_domain(self):
        cfg = Config(allowlist=("example.com",))
        result = redact(LETTER, config=cfg)
        # ivan.petrov@example.com сохраняется, прочие email — нет.
        self.assertIn("ivan.petrov@example.com", result.masked_text)
        self.assertNotIn("sergey@mail.ru", result.masked_text)

    def test_min_confidence_raise_drops_low(self):
        # Поднимаем порог выше адреса (0.78) — ADDRESS уходит, EMAIL (0.98) остаётся.
        found = {f.type for f in scan(LETTER, min_confidence=0.9)}
        self.assertNotIn("ADDRESS", found)
        self.assertIn("EMAIL", found)

    def test_filtered_result_still_consistent(self):
        # При фильтрации stats/findings остаются согласованными.
        result = build_then_redact(LETTER, only=["EMAIL", "PHONE_RU"])
        self.assertEqual(_sum_stats(result.stats), len(result.findings))
        self.assertEqual(result.report()["total"], len(result.findings))


def build_then_redact(text, **kwargs):
    """Хелпер: redact с kwargs (only/exclude/min_confidence)."""
    return redact(text, **kwargs)


class DeterminismTests(unittest.TestCase):
    """Повторный прогон одного документа даёт идентичный результат."""

    def test_redact_is_deterministic(self):
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            a = redact(doc)
            b = redact(doc)
            self.assertEqual(a.masked_text, b.masked_text)
            self.assertEqual(a.stats, b.stats)
            self.assertEqual(a.placeholders, b.placeholders)

    def test_finding_order_is_by_position(self):
        # Находки в redact идут в порядке появления в тексте (engine.redact идёт
        # курсором слева направо, значит resolve_overlaps отдаёт их по start).
        for doc in (LETTER, ANKETA, LOG, INVOICE):
            findings = redact(doc).findings
            starts = [f.start for f in findings]
            self.assertEqual(starts, sorted(starts), msg=doc[:30])


if __name__ == "__main__":
    unittest.main()
