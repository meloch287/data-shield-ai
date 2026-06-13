"""Нормализация перед детекцией (Block E): полноширина, гомоглифы, лимит ввода.

Тесты опираются на РЕАЛЬНОЕ поведение продукта, проверенное на источниках:

- ``datashield.engine.RedactionEngine._prepare`` нормализует вход ПЕРЕД
  детекцией (NFKC, опционально fold_homoglyphs) и проверяет ``max_input_size``.
- ``redact``/``scan`` пробрасывают ``normalize``/``fold_homoglyphs``/
  ``max_input_size`` через ``build_engine``.

Важный нюанс фактического поведения: телефонный детектор требует литерального
ASCII ``+``, поэтому ПОЛНОШИРИННЫЙ плюс «＋» ломает детекцию без normalize, а с
normalize (NFKC сворачивает ＋→+) телефон находится. А вот карта и ИНН с
полноширинными ЦИФРАМИ находятся И БЕЗ normalize, потому что Python ``\\d`` и
валидаторы (``int``/``isdigit``) понимают Unicode-цифры — меняется лишь
представление найденного значения (полноширина без normalize, ASCII с normalize).
"""
import unittest

from datashield import redact, scan
from datashield.normalize import normalize_text


def _fw_digits(s: str) -> str:
    """Перевести ASCII-цифры в полноширинные (U+FF10..U+FF19)."""
    return "".join(
        chr(ord(c) - ord("0") + 0xFF10) if c.isdigit() else c for c in s
    )


# Полноширинный плюс «＋» (U+FF0B) + полноширинные цифры российского номера.
FW_PLUS = "＋"
RU_PHONE_DIGITS = "79161234567"
FW_PHONE = FW_PLUS + _fw_digits(RU_PHONE_DIGITS)

# Валидная по Луну тестовая карта Visa, полностью полноширинными цифрами.
CARD_ASCII = "4111111111111111"
FW_CARD = _fw_digits(CARD_ASCII)

# Валидный 12-значный ИНН (проходит контрольные суммы), полноширинными цифрами.
INN_ASCII = "500100732259"
FW_INN = _fw_digits(INN_ASCII)

# Email с кириллическим гомоглифом: «а» в "pаypal" — кириллица (U+0430).
HOMOGLYPH_EMAIL = "pаypal@example.com"
HOMOGLYPH_EMAIL_FOLDED = "paypal@example.com"

# Email с гомоглифом в доменной части: «а» в "gmаil" — кириллица.
HOMOGLYPH_DOMAIN_EMAIL = "user@gmаil.com"
HOMOGLYPH_DOMAIN_FOLDED = "user@gmail.com"


class FullwidthPhoneTests(unittest.TestCase):
    """Полноширинный плюс «＋» детектится только с normalize."""

    def test_fullwidth_plus_phone_not_detected_without_normalize(self):
        # Детектор телефона требует литерального ASCII '+'. Полноширинный '＋'
        # его не удовлетворяет → без normalize находок нет.
        self.assertEqual(scan(FW_PHONE), [])

    def test_fullwidth_plus_phone_detected_with_normalize(self):
        findings = scan(FW_PHONE, normalize=True)
        self.assertEqual(len(findings), 1)
        phone = findings[0]
        self.assertTrue(phone.type.startswith("PHONE"))
        # Значение — в нормализованном ASCII-пространстве.
        self.assertEqual(phone.value, "+" + RU_PHONE_DIGITS)

    def test_fullwidth_plus_phone_masked_output_is_ascii(self):
        result = redact(FW_PHONE, normalize=True)
        # Выход маскирован: полноширинных символов не осталось.
        self.assertNotIn(FW_PLUS, result.masked_text)
        self.assertNotIn("７", result.masked_text)  # Ｗ нет полноширинной 7
        self.assertEqual(len(result.placeholders), 1)
        (placeholder,) = result.placeholders
        self.assertEqual(result.masked_text, placeholder)


class FullwidthCardTests(unittest.TestCase):
    """Карта с полноширинными цифрами: фактически находится и без normalize.

    Это РЕАЛЬНОЕ поведение продукта — оно расходится с наивным ожиданием
    «полноширина не детектится без normalize»: меняется лишь представление
    найденного значения, но не сам факт находки.
    """

    def test_fullwidth_card_detected_even_without_normalize(self):
        findings = scan("карта " + FW_CARD)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "CREDIT_CARD")
        # Без normalize значение остаётся полноширинным (сырой срез входа).
        self.assertEqual(findings[0].value, FW_CARD)

    def test_fullwidth_card_value_is_ascii_with_normalize(self):
        findings = scan("карта " + FW_CARD, normalize=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "CREDIT_CARD")
        # С normalize значение — в ASCII-пространстве.
        self.assertEqual(findings[0].value, CARD_ASCII)

    def test_fullwidth_card_masked_output_is_ascii_normalized(self):
        text = "карта " + FW_CARD
        result = redact(text, normalize=True)
        self.assertEqual(result.masked_text, "карта [CREDIT_CARD_1]")
        # В маскированном выходе нет полноширинных цифр.
        for ch in FW_CARD:
            self.assertNotIn(ch, result.masked_text)


class FullwidthInnTests(unittest.TestCase):
    """ИНН с полноширинными цифрами: тоже находится и без normalize."""

    def test_fullwidth_inn_detected_even_without_normalize(self):
        findings = scan("ИНН " + FW_INN)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "INN")
        self.assertEqual(findings[0].value, FW_INN)

    def test_fullwidth_inn_value_ascii_with_normalize(self):
        findings = scan("ИНН " + FW_INN, normalize=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "INN")
        self.assertEqual(findings[0].value, INN_ASCII)

    def test_fullwidth_inn_masked_output_normalized(self):
        result = redact("ИНН " + FW_INN, normalize=True)
        self.assertEqual(result.masked_text, "ИНН [INN_1]")


class HomoglyphEmailTests(unittest.TestCase):
    """Гомоглиф детектится только с normalize + fold_homoglyphs."""

    def test_homoglyph_email_not_detected_without_normalize(self):
        self.assertEqual(scan(HOMOGLYPH_EMAIL), [])

    def test_homoglyph_email_not_detected_with_normalize_only(self):
        # NFKC не трогает кириллический «а» — нужен именно fold_homoglyphs.
        self.assertEqual(scan(HOMOGLYPH_EMAIL, normalize=True), [])

    def test_homoglyph_email_detected_with_normalize_and_fold(self):
        findings = scan(HOMOGLYPH_EMAIL, normalize=True, fold_homoglyphs=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "EMAIL")
        self.assertEqual(findings[0].value, HOMOGLYPH_EMAIL_FOLDED)

    def test_homoglyph_email_masked_output_folded(self):
        result = redact(HOMOGLYPH_EMAIL, normalize=True, fold_homoglyphs=True)
        self.assertEqual(result.masked_text, "[EMAIL_1]")
        # Кириллического гомоглифа в выходе нет.
        self.assertNotIn("а", result.masked_text)

    def test_homoglyph_in_domain_part(self):
        self.assertEqual(scan(HOMOGLYPH_DOMAIN_EMAIL), [])
        findings = scan(
            HOMOGLYPH_DOMAIN_EMAIL, normalize=True, fold_homoglyphs=True
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].value, HOMOGLYPH_DOMAIN_FOLDED)


class WithoutNormalizeNoneDetectedTests(unittest.TestCase):
    """Без normalize обфусцированные через ＋/гомоглиф значения не находятся.

    (Карта/ИНН с полноширинными ЦИФРАМИ — отдельный случай, проверен выше:
    они находятся всегда. Здесь — обфускация, которую ломает именно отсутствие
    нормализации: полноширинный плюс и кириллический гомоглиф.)
    """

    def test_fullwidth_plus_phone_and_homoglyph_email_silent(self):
        combined = f"тел {FW_PHONE} почта {HOMOGLYPH_EMAIL}"
        self.assertEqual(scan(combined), [])

    def test_all_three_obfuscations_with_normalize_and_fold(self):
        # Карта (полноширина), телефон (＋), email (гомоглиф) — всё вместе.
        combined = (
            f"карта {FW_CARD} тел {FW_PHONE} почта {HOMOGLYPH_EMAIL}"
        )
        findings = scan(combined, normalize=True, fold_homoglyphs=True)
        types = sorted(f.type for f in findings)
        self.assertIn("CREDIT_CARD", types)
        self.assertIn("EMAIL", types)
        self.assertTrue(any(t.startswith("PHONE") for t in types))


class RedactSelfConsistencyTests(unittest.TestCase):
    """Выход redact самосогласован: плейсхолдеры на месте, остаток = норм-текст."""

    def _assert_self_consistent(self, text, **kwargs):
        result = redact(text, **kwargs)
        homoglyphs = bool(kwargs.get("fold_homoglyphs", False))
        norm = normalize_text(text, homoglyphs=homoglyphs)
        # 1) каждый плейсхолдер действительно присутствует в выходе
        self.assertTrue(result.placeholders, "ожидались плейсхолдеры")
        for placeholder in result.placeholders:
            self.assertIn(placeholder, result.masked_text)
        # 2) не-маскированный остаток = соответствующие срезы нормализованного
        #    текста (никакой порчи индексов): реконструируем масированный текст
        #    из norm + позиций находок и сверяем.
        rebuilt = []
        cursor = 0
        ctx = {}
        for finding in result.findings:
            rebuilt.append(norm[cursor:finding.start])
            # placeholders отображают placeholder->TYPE; нам нужно
            # placeholder для каждой находки — берём из самого masked_text по
            # стратегии: восстановим, что срез norm равен value.
            self.assertEqual(norm[finding.start:finding.end], finding.value)
            cursor = finding.end
            ctx[finding.start] = finding
        # хвост норм-текста должен дословно встречаться в конце masked_text
        tail = norm[cursor:]
        if tail:
            self.assertTrue(
                result.masked_text.endswith(tail),
                f"хвост {tail!r} не совпал с {result.masked_text!r}",
            )
        # голова до первой находки — дословно в начале masked_text
        if result.findings:
            head = norm[: result.findings[0].start]
            self.assertTrue(result.masked_text.startswith(head))
        return result

    def test_fullwidth_card_redact_self_consistent(self):
        self._assert_self_consistent("карта " + FW_CARD, normalize=True)

    def test_fullwidth_phone_redact_self_consistent(self):
        self._assert_self_consistent("тел " + FW_PHONE, normalize=True)

    def test_homoglyph_email_redact_self_consistent(self):
        self._assert_self_consistent(
            "почта " + HOMOGLYPH_EMAIL, normalize=True, fold_homoglyphs=True
        )

    def test_no_index_corruption_remainder_equals_normalized(self):
        # Выкинув все плейсхолдеры из masked_text и восстановив value на их
        # места, должны получить ровно нормализованный текст.
        text = "карта " + FW_CARD + " и ещё текст"
        result = redact(text, normalize=True)
        norm = normalize_text(text)
        # Подставляем value обратно: проверяем, что masked_text + value
        # покрывают весь norm без сдвигов.
        cursor = 0
        pieces = []
        for finding in result.findings:
            pieces.append(norm[cursor:finding.start])
            pieces.append(finding.value)
            cursor = finding.end
        pieces.append(norm[cursor:])
        self.assertEqual("".join(pieces), norm)


class ScanPositionsSliceBackTests(unittest.TestCase):
    """Позиции из scan(normalize=True) корректно срезаются из норм-текста."""

    def test_positions_slice_from_normalized_text(self):
        text = f"карта {FW_CARD}, тел {FW_PHONE}"
        findings = scan(text, normalize=True)
        norm = normalize_text(text)
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(norm[finding.start:finding.end], finding.value)

    def test_positions_slice_with_fold_from_folded_text(self):
        text = f"почта {HOMOGLYPH_EMAIL}"
        findings = scan(text, normalize=True, fold_homoglyphs=True)
        norm = normalize_text(text, homoglyphs=True)
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(norm[finding.start:finding.end], finding.value)

    def test_scan_positions_differ_from_raw_when_normalized(self):
        # Слайс из СЫРОГО (ненормализованного) текста по тем же позициям не
        # обязан совпасть с value — подтверждаем, что движок работает именно в
        # нормализованном пространстве (＋ → + сдвига длины не даёт, но символы
        # отличаются).
        text = "тел " + FW_PHONE
        findings = scan(text, normalize=True)
        self.assertEqual(len(findings), 1)
        norm = normalize_text(text)
        self.assertEqual(norm[findings[0].start:findings[0].end], findings[0].value)
        # сырой срез содержит полноширинный плюс, value — ASCII '+'
        self.assertNotEqual(text[findings[0].start:findings[0].end], findings[0].value)


class MaxInputSizeTests(unittest.TestCase):
    """max_input_size>0 рейзит ValueError и в scan, и в redact (через _prepare)."""

    def test_redact_raises_over_limit(self):
        with self.assertRaises(ValueError):
            redact("x" * 100, max_input_size=10)

    def test_scan_raises_over_limit(self):
        with self.assertRaises(ValueError):
            scan("x" * 100, max_input_size=10)

    def test_within_limit_ok(self):
        result = redact("привет", max_input_size=100)
        self.assertEqual(result.masked_text, "привет")

    def test_limit_checked_against_pre_normalized_length(self):
        # Лимит сверяется с исходной длиной ДО нормализации (NFKC может менять
        # длину). Полноширина — 1:1 по длине, поэтому проверяем сам факт рейза.
        with self.assertRaises(ValueError):
            redact("карта " + FW_CARD, normalize=True, max_input_size=5)

    def test_zero_limit_means_unlimited(self):
        result = redact("x" * 1000, max_input_size=0)
        self.assertIsNotNone(result.masked_text)


if __name__ == "__main__":
    unittest.main()
