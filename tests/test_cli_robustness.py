"""Тесты устойчивости CLI: нормализация, гомоглифы, лимит размера входа.

Покрывает флаги Блока E у команд redact/scan:
  --normalize          NFKC-нормализация (ловит полноширинные цифры)
  --fold-homoglyphs    сворачивание кириллических двойников в смешанных токенах
  --max-input-size N   отказ при превышении лимита длины

Все утверждения отражают ФАКТИЧЕСКОЕ поведение продукта, проверенное на
реальных источниках datashield (normalize.py, engine.py, cli.py,
detectors/regex_intl.py).

ВАЖНО о полноширинных цифрах: спецификация утверждает, что без --normalize
полноширинная карта НЕ детектируется. Это НЕ так для детектора credit_card в
этом коде: его regex и Луна-валидатор Unicode-терпимы (\\d, ch.isdigit(),
int(ch) принимают полноширину), поэтому валидная по Луну полноширинная карта
ловится и БЕЗ нормализации. Чистый «переключатель» полноширины в этом
коде — IPv4: его regex использует ASCII-классы ([0-9]/диапазоны/\\.),
поэтому полноширинный IP без NFKC не матчится, а с --normalize — матчится.
Тесты ниже отражают это реальное поведение.
"""
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main


def run(argv, stdin_text=None):
    """Запуск CLI с подменой stdin (паттерн из tests/test_cli.py)."""
    out, err = io.StringIO(), io.StringIO()
    real_stdin = None
    if stdin_text is not None:
        real_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        if stdin_text is not None:
            sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


def _fullwidth(text):
    """ASCII-цифры -> полноширинные (U+FF10..U+FF19), остальное без изменений."""
    return "".join(
        chr(ord(ch) - ord("0") + 0xFF10) if ch.isdigit() else ch for ch in text
    )


# Полноширинные эквиваленты, проверенные на реальном движке.
FULLWIDTH_IP = "ip " + _fullwidth("192.168.0.1")
FULLWIDTH_CARD = "карта " + _fullwidth("4111 1111 1111 1111")  # валиден по Луну
# Гомоглифный email: 'о' в "john" — кириллическая (U+043E), а не латинская 'o'.
HOMOGLYPH_EMAIL = "пиши на jоhn@gmail.com"


class NormalizeFullwidthTests(unittest.TestCase):
    """--normalize и полноширинные цифры (реальный переключатель — IPv4)."""

    def test_redact_normalize_masks_fullwidth_ip(self):
        # С --normalize полноширинный IP нормализуется и маскируется,
        # вывод — в нормализованном пространстве (плейсхолдер, без полноширины).
        code, out, _ = run(["redact", "--normalize"], stdin_text=FULLWIDTH_IP)
        self.assertEqual(code, 0)
        self.assertIn("[IP_1]", out)
        # полноширинные цифры в выводе не остались
        self.assertNotIn("１", out)
        self.assertNotIn("９", out)

    def test_scan_normalize_finds_fullwidth_ip(self):
        code, out, _ = run(["scan", "--json", "--normalize"], stdin_text=FULLWIDTH_IP)
        self.assertEqual(code, 0)
        self.assertIn('"type": "IP"', out)

    def test_default_leaves_fullwidth_ip_undetected(self):
        # Без флагов полноширинный IP не детектируется regex'ом IPv4 (ASCII-классы).
        code, out, _ = run(["redact"], stdin_text=FULLWIDTH_IP)
        self.assertEqual(code, 0)
        self.assertNotIn("[IP_", out)
        # исходные полноширинные цифры сохранены как есть (нормализации не было)
        self.assertIn("１", out)

    def test_scan_default_fullwidth_ip_not_found(self):
        code, out, _ = run(["scan"], stdin_text=FULLWIDTH_IP)
        self.assertEqual(code, 0)
        self.assertIn("не найдено", out.lower())

    def test_fullwidth_card_detected_even_without_normalize(self):
        # ФАКТ продукта: детектор карты Unicode-терпим, поэтому валидная по Луну
        # полноширинная карта ловится и БЕЗ --normalize (вопреки тексту спеки).
        code, out, _ = run(["redact"], stdin_text=FULLWIDTH_CARD)
        self.assertEqual(code, 0)
        self.assertIn("[CREDIT_CARD_1]", out)

    def test_fullwidth_card_with_normalize_masks_in_normalized_space(self):
        # С --normalize карта тоже маскируется; вывод в нормализованном
        # пространстве, полноширинных цифр в выводе нет.
        code, out, _ = run(["redact", "--normalize"], stdin_text=FULLWIDTH_CARD)
        self.assertEqual(code, 0)
        self.assertIn("[CREDIT_CARD_1]", out)
        self.assertNotIn("１", out)


class FoldHomoglyphsTests(unittest.TestCase):
    """--fold-homoglyphs ловит email с кириллическим двойником."""

    def test_fold_homoglyphs_catches_homoglyph_email(self):
        # Сворачивание работает только при --normalize (fold идёт внутри
        # engine._prepare, а оно вызывается лишь когда normalize=True).
        code, out, _ = run(
            ["redact", "--normalize", "--fold-homoglyphs"],
            stdin_text=HOMOGLYPH_EMAIL,
        )
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)
        # исходный кириллический символ в выводе не остался
        self.assertNotIn("jоhn", out)

    def test_scan_fold_homoglyphs_finds_email(self):
        code, out, _ = run(
            ["scan", "--json", "--normalize", "--fold-homoglyphs"],
            stdin_text=HOMOGLYPH_EMAIL,
        )
        self.assertEqual(code, 0)
        self.assertIn('"type": "EMAIL"', out)

    def test_default_leaves_homoglyph_email_undetected(self):
        # Без флагов смешанный кириллица/латиница email не матчит regex email.
        code, out, _ = run(["redact"], stdin_text=HOMOGLYPH_EMAIL)
        self.assertEqual(code, 0)
        self.assertNotIn("[EMAIL_", out)

    def test_normalize_only_does_not_catch_homoglyph_email(self):
        # NFKC сам по себе не трогает кириллические двойники — нужен fold.
        code, out, _ = run(["redact", "--normalize"], stdin_text=HOMOGLYPH_EMAIL)
        self.assertEqual(code, 0)
        self.assertNotIn("[EMAIL_", out)

    def test_fold_without_normalize_is_noop(self):
        # --fold-homoglyphs без --normalize ничего не сворачивает (fold живёт
        # внутри _prepare под условием self.normalize).
        code, out, _ = run(
            ["scan", "--fold-homoglyphs"], stdin_text=HOMOGLYPH_EMAIL
        )
        self.assertEqual(code, 0)
        self.assertIn("не найдено", out.lower())


class MaxInputSizeTests(unittest.TestCase):
    """--max-input-size N: превышение лимита."""

    OVERSIZED = "this is a long line of text"  # 27 символов

    def test_redact_oversized_exits_1_with_message(self):
        code, out, err = run(
            ["redact", "--max-input-size", "10"], stdin_text=self.OVERSIZED
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")  # masked-вывод не пишется
        self.assertIn("превышает лимит", err)
        self.assertIn("10", err)

    def test_redact_oversized_message_reports_actual_length(self):
        code, _, err = run(
            ["redact", "--max-input-size", "10"], stdin_text=self.OVERSIZED
        )
        self.assertEqual(code, 1)
        self.assertIn(str(len(self.OVERSIZED)), err)

    def test_redact_within_limit_succeeds(self):
        code, out, _ = run(
            ["redact", "--max-input-size", "100"], stdin_text="почта a@b.com"
        )
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)

    def test_redact_zero_limit_means_no_limit(self):
        # 0 трактуется как «без лимита» (проверка `self.max_input_size and ...`).
        big = "x" * 5000 + " a@b.com"
        code, out, _ = run(
            ["redact", "--max-input-size", "0"], stdin_text=big
        )
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)

    def test_scan_oversized_exits_1_consistent_with_redact(self):
        # Исправлено: превышение лимита размера — рантайм-ошибка (код 1),
        # одинаково для redact и scan. (Раньше scan ошибочно давал 2.)
        code, _, err = run(
            ["scan", "--max-input-size", "10"], stdin_text=self.OVERSIZED
        )
        self.assertEqual(code, 1)
        self.assertIn("превышает лимит", err)


class FlagCombinationTests(unittest.TestCase):
    """Флаги Блока E совместимы с --preset / --strategy."""

    def test_normalize_combines_with_strategy_hash(self):
        # --normalize + --strategy hash: полноширинный IP маскируется хешем.
        code, out, _ = run(
            ["redact", "--normalize", "--strategy", "hash"], stdin_text=FULLWIDTH_IP
        )
        self.assertEqual(code, 0)
        self.assertIn("[IP_", out)
        self.assertNotIn("[IP_1]", out)  # хеш-стратегия, не порядковый номер

    def test_fold_homoglyphs_combines_with_preset_gdpr(self):
        # GDPR-пресет пропускает EMAIL; вместе с fold ловит гомоглифный email.
        code, out, _ = run(
            ["redact", "--normalize", "--fold-homoglyphs", "--preset", "gdpr"],
            stdin_text=HOMOGLYPH_EMAIL,
        )
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)

    def test_max_input_size_combines_with_preset_and_strategy(self):
        # Лимит проверяется в _prepare независимо от пресета/стратегии -> exit 1.
        code, _, err = run(
            [
                "redact",
                "--max-input-size",
                "10",
                "--preset",
                "pci-dss",
                "--strategy",
                "hash",
            ],
            stdin_text="this is a long line of text",
        )
        self.assertEqual(code, 1)
        self.assertIn("превышает лимит", err)

    def test_normalize_with_preset_pci_masks_fullwidth_card(self):
        # PCI-DSS включает CREDIT_CARD; --normalize маскирует полноширинную карту.
        code, out, _ = run(
            ["redact", "--normalize", "--preset", "pci-dss"],
            stdin_text=FULLWIDTH_CARD,
        )
        self.assertEqual(code, 0)
        self.assertIn("[CREDIT_CARD_1]", out)


if __name__ == "__main__":
    unittest.main()
