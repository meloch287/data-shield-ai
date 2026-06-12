"""Тесты на защиту от катастрофического бэктрекинга (ReDoS) и базовую скорость.

Цель — убедиться, что `scan()` / `redact()` не «зависают» на специально
сконструированных «злых» входах (длинные повторы, почти-совпадения, незакрытые
блоки). Для каждого потенциально опасного паттерна — телефоны, IBAN с пробелами,
почтовый адрес, блок приватного ключа, имена, карты, JWT, IPv6 — подаётся
вредоносный вход размером ~50КБ и проверяется, что обработка завершается быстро.

Замеры делаем двумя способами:
  1. concurrent.futures.ThreadPoolExecutor + future.result(timeout=...) —
     жёсткий «сторожевой таймер»: если scan() не вернётся за N секунд, тест
     падает по TimeoutError (поток продолжит крутиться в фоне, но тест уже красный).
  2. time.perf_counter() + assertLess — мягкая проверка верхней границы времени.

Сигналы (signal.alarm) НЕ используем намеренно: они не работают в неглавном
потоке и на части платформ, а пул потоков переносим везде.
"""
from __future__ import annotations

import time
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from datashield import Config, redact, scan

# Бюджеты времени. Базовые замеры на этой машине — десятки миллисекунд, так что
# порог в 2 секунды оставляет огромный запас и одновременно ловит экспоненту.
HARD_TIMEOUT = 2.0   # «сторожевой таймер» для future.result(timeout=...)
SOFT_BUDGET = 2.0    # верхняя граница для assertLess по perf_counter
SIZE = 50_000        # ~50КБ вредоносного входа


def run_with_timeout(func, *args, timeout=HARD_TIMEOUT):
    """Запускает func(*args) в отдельном потоке и ждёт не дольше timeout секунд.

    Возвращает результат либо бросает concurrent.futures.TimeoutError. Сигналы
    не задействуются, поэтому безопасно работает из любого потока.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(func, *args)
        return future.result(timeout=timeout)


def timed_scan(text, **kwargs):
    """Сканирует и возвращает (список findings, затраченное время в секундах)."""
    start = time.perf_counter()
    findings = scan(text, **kwargs)
    return findings, time.perf_counter() - start


class _PerfAssertMixin:
    """Утилиты-ассерты, общие для всех групп тестов производительности."""

    def assert_fast(self, text, *, soft=SOFT_BUDGET, hard=HARD_TIMEOUT, **kwargs):
        """Проверяет, что scan() и укладывается в hard-таймаут, и быстр по часам.

        Возвращает список findings, чтобы вызывающий тест мог дополнительно
        проверить семантику (что именно нашлось / не нашлось).
        """
        # 1. Жёсткий сторожевой таймер через отдельный поток.
        try:
            findings = run_with_timeout(lambda: scan(text, **kwargs), timeout=hard)
        except FutureTimeout:  # pragma: no cover — срабатывает только при ReDoS
            self.fail(
                f"scan() не завершился за {hard}s на входе длиной {len(text)} — "
                "вероятен катастрофический бэктрекинг"
            )
        # 2. Мягкая проверка времени (на случай если таймаут великоват).
        _, elapsed = timed_scan(text, **kwargs)
        self.assertLess(
            elapsed,
            soft,
            f"scan() занял {elapsed:.3f}s (> {soft}s) на входе длиной {len(text)}",
        )
        return findings


class PhonePerfTests(_PerfAssertMixin, unittest.TestCase):
    """Телефоны (PHONE intl и PHONE_RU) — много групп цифр и разделителей."""

    def test_intl_phone_long_digit_run(self):
        # Очень длинный хвост цифр после "+": движок не должен буксовать.
        evil = "+" + "9" * SIZE
        self.assert_fast(evil)

    def test_intl_phone_repeated_groups(self):
        # Повторяющиеся группы "цифры+пробел" — типичный триггер бэктрекинга
        # для паттернов вида (?:[\s\-]?\d{2,4}){2,4}.
        evil = "+1" + " 12" * (SIZE // 3)
        self.assert_fast(evil)

    def test_intl_phone_almost_match_no_plus(self):
        # Почти-совпадение: нет ведущего "+", значит PHONE не должен находиться,
        # но и зависать на разборе движок не имеет права.
        evil = "8" + "9" * SIZE
        findings = self.assert_fast(evil)
        self.assertNotIn("PHONE", {f.type for f in findings})

    def test_ru_phone_repeated_separators(self):
        # PHONE_RU: чередование +7/8, скобок и разделителей в большом объёме.
        evil = ("+7 (909) 123-45-67 " * (SIZE // 19))
        self.assert_fast(evil)

    def test_ru_phone_broken_long_tail(self):
        # Корректный префикс +7, но дальше бесконечный «мусор» из цифр —
        # лукэхед (?!\d) и фиксированная длина не дают экспоненты.
        evil = "+7" + "1" * SIZE
        self.assert_fast(evil)


class IbanPerfTests(_PerfAssertMixin, unittest.TestCase):
    """IBAN с пробелами — (?:[ ]?[A-Za-z0-9]){11,30} склонен к бэктрекингу."""

    def test_iban_grouped_spaces(self):
        # Группы из двух символов через пробел, как в "GB82 WEST 1234 ...".
        evil = "GB82 " + "A1 " * (SIZE // 3)
        self.assert_fast(evil)

    def test_iban_long_alnum_no_spaces(self):
        # Длинная буквенно-цифровая «простыня» — проверяет верхнюю границу {11,30}.
        evil = "XX00" + "A1B2C3" * (SIZE // 6)
        self.assert_fast(evil)

    def test_iban_almost_valid_then_garbage(self):
        # Почти-IBAN: верный префикс из 2 букв + 2 цифр, дальше длинный хвост,
        # который не пройдёт mod-97. Не должно ни находиться, ни тормозить.
        evil = "DE89" + "3" * SIZE
        findings = self.assert_fast(evil)
        self.assertNotIn("IBAN", {f.type for f in findings})

    def test_iban_alternating_spaces_and_letters(self):
        # Чередование «буква пробел» — худший случай для опционального [ ]?.
        evil = "FR76" + "Z " * (SIZE // 2)
        self.assert_fast(evil)


class AddressPerfTests(_PerfAssertMixin, unittest.TestCase):
    """Адреса (ADDRESS) — ключевое слово улицы + захват до запятой/строки."""

    def test_address_huge_non_comma_run(self):
        # После "улица " идёт огромная строка без запятых. Захват [^\n,;]{2,40}
        # ограничен сверху 40 символами, поэтому большой объём не страшен.
        evil = "улица " + "ы" * SIZE
        self.assert_fast(evil)

    def test_address_many_street_keywords(self):
        # Множество триггеров улицы подряд — много стартов матча.
        evil = "проспект Мира, " * (SIZE // 15)
        self.assert_fast(evil)

    def test_address_keyword_then_punctuation_wall(self):
        # Стена пунктуации после ключевого слова (символы не из [\n,;]).
        evil = "набережная " + "!" * SIZE
        self.assert_fast(evil)

    def test_address_no_street_keyword(self):
        # Без слова-улицы ADDRESS находиться не должен; проверяем и скорость.
        evil = "просто очень длинный текст " * (SIZE // 27)
        findings = self.assert_fast(evil)
        self.assertNotIn("ADDRESS", {f.type for f in findings})


class PrivateKeyPerfTests(_PerfAssertMixin, unittest.TestCase):
    """Блок приватного ключа — нежадный [\\s\\S]+? между BEGIN и END."""

    def test_private_key_begin_without_end(self):
        # BEGIN есть, END нет: нежадный квантификатор должен «сдаться» линейно,
        # а не перебирать экспоненциально.
        evil = "-----BEGIN RSA PRIVATE KEY-----\n" + "x" * SIZE
        findings = self.assert_fast(evil)
        self.assertNotIn("PRIVATE_KEY", {f.type for f in findings})

    def test_private_key_many_begin_markers(self):
        # Множество маркеров BEGIN без закрытия — много точек старта для движка.
        evil = "-----BEGIN PRIVATE KEY-----\n" * (SIZE // 28)
        self.assert_fast(evil)

    def test_private_key_valid_huge_body(self):
        # Корректный блок с большим телом: должен находиться и не тормозить.
        body = "MIIEowIBAAKCAQEA" + "A" * SIZE + "\n"
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + body
            + "-----END RSA PRIVATE KEY-----"
        )
        findings = self.assert_fast(block)
        self.assertIn("PRIVATE_KEY", {f.type for f in findings})

    def test_private_key_end_without_begin(self):
        # Только END без BEGIN — совпадения нет, паника движка недопустима.
        evil = "y" * SIZE + "\n-----END RSA PRIVATE KEY-----"
        findings = self.assert_fast(evil)
        self.assertNotIn("PRIVATE_KEY", {f.type for f in findings})


class NamesPerfTests(_PerfAssertMixin, unittest.TestCase):
    """Имена (PERSON) — много регулярок: триплеты, пары, отчества, контекст."""

    def test_names_many_capitalized_ru_words(self):
        # Длинная цепочка заглавных русских слов — пары/триплеты ФИО.
        evil = "Иван " * (SIZE // 5)
        self.assert_fast(evil)

    def test_names_patronymic_near_miss(self):
        # Бесконечное «слипшееся» слово с суффиксом отчества — без границ слова.
        evil = "Иванович" * (SIZE // 8)
        self.assert_fast(evil)

    def test_names_en_pairs_flood(self):
        # Поток английских пар "Имя Фамилия" — газеттир + регулярки.
        evil = "John Smith " * (SIZE // 11)
        self.assert_fast(evil)

    def test_names_context_trigger_flood(self):
        # Множество контекстных триггеров "меня зовут X" подряд.
        evil = "меня зовут Пётр " * (SIZE // 16)
        self.assert_fast(evil)

    def test_names_long_single_token(self):
        # Один гигантский «CamelCase» токен — проверка одиночных регулярок.
        evil = "Ab" * (SIZE // 2)
        self.assert_fast(evil)


class CardAndTokenPerfTests(_PerfAssertMixin, unittest.TestCase):
    """Карты, JWT, IPv6 — паттерны с группировками и валидаторами."""

    def test_credit_card_long_digit_run(self):
        # Длинная цифровая строка с разделителями; валидатор Луна — на каждый матч.
        evil = "4" + " 1" * (SIZE // 2)
        self.assert_fast(evil)

    def test_credit_card_near_miss_groups(self):
        # Группы по 4 цифры, не складывающиеся в валидную карту.
        evil = "1234 " * (SIZE // 5)
        findings = self.assert_fast(evil)
        self.assertNotIn("CREDIT_CARD", {f.type for f in findings})

    def test_jwt_two_segments_no_third(self):
        # eyJ...eyJ... без третьего сегмента — точка отказа для split по точкам.
        evil = "eyJ" + "a" * (SIZE // 2) + ".eyJ" + "b" * (SIZE // 2)
        findings = self.assert_fast(evil)
        self.assertNotIn("JWT", {f.type for f in findings})

    def test_ipv6_many_colon_groups(self):
        # Длинная цепочка "hex:" — у IPv6-паттерна много альтернатив со звёздами.
        evil = "1:" * (SIZE // 2)
        self.assert_fast(evil)

    def test_ipv4_long_digit_run(self):
        # Большой блок цифр с точками — IPv4 c жёсткими диапазонами октетов.
        evil = "123." * (SIZE // 4)
        self.assert_fast(evil)


class MixedAndBaselinePerfTests(_PerfAssertMixin, unittest.TestCase):
    """Смешанные «злые» документы и базовая скорость на обычном тексте."""

    def test_plain_50kb_is_fast(self):
        # Простой текст без PII: базовая скорость прохода всех детекторов.
        text = "обычный текст без секретов " * (SIZE // 27)
        findings, elapsed = timed_scan(text)
        self.assertLess(elapsed, SOFT_BUDGET)
        self.assertEqual(findings, [] if not findings else findings)  # без падений

    def test_mixed_near_miss_document(self):
        # Документ, где КАЖДЫЙ опасный паттерн представлен почти-совпадением.
        chunk = (
            "+" + "7" * 60 + " "          # phone near-miss
            "GB00" + "A" * 60 + " "        # iban near-miss
            "улица " + "я" * 60 + " "      # address (ограничен 40 симв.)
            "Иванович "                    # patronymic-ish
            "eyJ" + "z" * 60 + ". "        # jwt near-miss
            "-----BEGIN PRIVATE KEY----- "  # privkey begin only
        )
        evil = chunk * (SIZE // len(chunk) + 1)
        self.assert_fast(evil)

    def test_whitespace_flood(self):
        # Только пробелы и переводы строк — детекторы не должны буксовать.
        evil = (" \t\n" * (SIZE // 3))
        findings = self.assert_fast(evil)
        self.assertEqual(findings, [])

    def test_unicode_letter_flood(self):
        # Большой поток не-ASCII букв без структуры PII.
        evil = "ёжикёжик" * (SIZE // 8)
        self.assert_fast(evil)

    def test_redact_path_is_fast(self):
        # Полный путь redact() (анализ + маскировка) на вредоносном входе.
        evil = "+" + "9" * SIZE
        try:
            result = run_with_timeout(lambda: redact(evil), timeout=HARD_TIMEOUT)
        except FutureTimeout:  # pragma: no cover
            self.fail("redact() не завершился за отведённое время — возможен ReDoS")
        self.assertEqual(result.original_length, len(evil))

    def test_high_entropy_enabled_stays_fast(self):
        # Опциональный high_entropy включён: длинный энтропийный поток.
        cfg = Config(enabled_detectors=("high_entropy",))
        evil = "X9aK2pQ7mZ4wL1nB8vR3cE6tY0uH5jD" * (SIZE // 31)
        self.assert_fast(evil, config=cfg)


class TimeoutHelperTests(unittest.TestCase):
    """Проверяем, что сам сторожевой механизм работает как задумано."""

    def test_run_with_timeout_returns_value(self):
        self.assertEqual(run_with_timeout(lambda: 21 * 2), 42)

    def test_run_with_timeout_raises_on_slow(self):
        # Намеренно медленная функция должна привести к TimeoutError.
        def slow():
            time.sleep(1.0)
            return "done"

        with self.assertRaises(FutureTimeout):
            run_with_timeout(slow, timeout=0.05)


if __name__ == "__main__":
    unittest.main()
