"""Бенчмарк ложных срабатываний (false positives) на чистых текстах.

Этот модуль НЕ проверяет отдельные детекторы — он измеряет, насколько «спокойно»
``scan()`` ведёт себя на правдоподобных текстах БЕЗ персональных данных:
новостные предложения (EN/RU), фрагменты кода, строки логов с таймстампами,
математика вида ``x = 3.14159``, версии ``1.2.3`` / ``v2.10.4``, UUID, git-хэши
(без префикса ``0x``), пути к файлам, цены, ISO-даты, проценты.

Метрика — суммарное число «попаданий» (text -> тип маски) по всему бенчмарку:
для каждого чистого текста считаем множество уникальных типов, которые сработали,
и складываем их размеры. На корректном детекторе это число должно быть малым.

Все значения собраны вручную и сверены с ФАКТИЧЕСКИМ поведением исходного кода
(``datashield.scan``), а не с предположениями. Поведение, наблюдаемое на момент
написания: все тексты из ``CLEAN_TEXTS`` дают РОВНО 0 ложных срабатываний.

Отдельно зафиксировано улучшение детектора: 4-частная версия вида ``1.2.3.4`` в
контексте сборки/версии БОЛЬШЕ НЕ детектируется как ``IP`` (version-context
подавление). 3-частные версии (``1.2.3``) тоже не путаются с IPv4. 4-частный
случай вынесен в отдельный тест, который теперь проверяет ОТСУТСТВИЕ находки.

Запуск только этого модуля:
    cd /Users/meloch287/Desktop/data-shield-ai && \
        python3 -m unittest tests.test_fp_benchmark -v
"""
import unittest
from collections import Counter

from datashield import redact, scan

# ---------------------------------------------------------------------------
# ~30+ правдоподобных ЧИСТЫХ текстов без PII. Каждый должен пройти БЕЗ масок.
#
# Про версии: берём 3-частные (1.2.3 / v2.10.4). 4-частная версия 1.2.3.4 в
# контексте сборки теперь корректно НЕ детектируется как IP — это проверяется в
# отдельном тесте ниже (test_accepted_fp_four_part_version).
# ---------------------------------------------------------------------------
CLEAN_TEXTS = [
    # --- Новости (English) ---
    "The central bank raised interest rates by 0.25 percent on Tuesday.",
    "Researchers published the study in a peer-reviewed journal last week.",
    "The company reported quarterly revenue of 4.2 billion dollars.",
    "Apple announced a new product line at its developer conference.",
    "The election results will be certified by the end of the month.",
    # --- Новости (Русский) ---
    "Совет директоров утвердил годовой отчёт на заседании в среду.",
    "Учёные опубликовали результаты исследования в научном журнале.",
    "Компания увеличила выручку на 12 процентов за квартал.",
    "Министерство представило новую программу развития регионов.",
    # --- Фрагменты кода ---
    "for i in range(10): print(i * 2)",
    "const sum = arr.reduce((a, b) => a + b, 0);",
    "def add(a, b):\n    return a + b",
    "SELECT id, name FROM users WHERE active = 1;",
    "git checkout -b feature/new-login",
    # --- Строки логов с таймстампами ---
    "2026-06-13 09:42:17 INFO Starting server on port 8080",
    "[2026-06-13T09:42:17Z] WARN cache miss for key user_settings",
    "2026/06/13 09:42:17 ERROR connection timeout after 30s",
    # --- Математика ---
    "x = 3.14159 and y = 2.71828",
    "The area equals pi * r squared.",
    "result = (a + b) / c * 100",
    # --- Версии (3-частные, не путаются с IPv4) ---
    "Upgraded to version 1.2.3 yesterday.",
    "Released v2.10.4 with bug fixes.",
    "Python 3.11.5 is now the default.",
    "Node v18.17.1 installed.",
    # --- UUID ---
    "session id 550e8400-e29b-41d4-a716-446655440000 created",
    "trace f47ac10b-58cc-4372-a567-0e02b2c3d479 logged",
    # --- git-хэши БЕЗ префикса 0x (иначе сработал бы ETH_ADDRESS) ---
    "commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 merged",
    "short hash 9fceb02 reverted",
    # --- Пути к файлам ---
    "Open the file at /usr/local/bin/python3 now.",
    "Config lives in C:\\Users\\admin\\config.yaml here.",
    "Edit ./src/components/Button.tsx today.",
    # --- Цены ---
    "The ticket costs $49.99 plus tax.",
    "Total: 1299 руб. за подписку.",
    # --- ISO-даты ---
    "The deadline is 2026-12-31 for all teams.",
    "Event scheduled on 2025-01-15.",
    # --- Проценты ---
    "Growth was 23.5% year over year.",
    "Battery at 87% remaining.",
]

# Порог: суммарно по всему бенчмарку допускаем не более 3 ложных «попаданий».
# Наблюдаемое значение на текущем коде — 0.
MAX_TOTAL_FALSE_HITS = 3


def _fired_types(text):
    """Множество уникальных типов, которые сработали на тексте."""
    return {f.type for f in scan(text)}


class FalsePositiveBenchmark(unittest.TestCase):
    """Совокупная частота ложных срабатываний на чистых текстах должна быть мала."""

    def test_benchmark_has_enough_samples(self):
        # Бенчмарк должен быть достаточно большим, чтобы регрессии всплывали.
        self.assertGreaterEqual(len(CLEAN_TEXTS), 30)

    def test_total_false_hits_below_threshold(self):
        """Суммарное число (текст -> тип маски) ложных попаданий должно быть малым.

        Для каждого чистого текста складываем число уникальных сработавших типов.
        Также собираем, КАКИЕ типы стреляли и на каких текстах — чтобы при
        регрессии в выводе теста было видно конкретного виновника.
        """
        total_false_hits = 0
        fired_by_type = Counter()
        offenders = []
        for text in CLEAN_TEXTS:
            types = _fired_types(text)
            if types:
                total_false_hits += len(types)
                for t in sorted(types):
                    fired_by_type[t] += 1
                offenders.append((sorted(types), text))

        # Печатаем диагностику, чтобы регрессия была видна в логе прогона.
        if offenders:
            print("\n[FP-benchmark] неожиданные срабатывания на чистых текстах:")
            for types, text in offenders:
                print(f"  {types}: {text[:70]!r}")
            print(f"[FP-benchmark] по типам: {dict(fired_by_type)}")
        else:
            print("\n[FP-benchmark] ложных срабатываний нет (0 на всём наборе).")

        self.assertLessEqual(
            total_false_hits,
            MAX_TOTAL_FALSE_HITS,
            msg=(
                f"Слишком много ложных срабатываний: {total_false_hits} "
                f"(порог {MAX_TOTAL_FALSE_HITS}). Виновники: {offenders}"
            ),
        )

    def test_clean_texts_produce_no_findings(self):
        """Зафиксированное фактическое поведение: чистые тексты не дают находок.

        Это более строгая (поэлементная) проверка того же набора. Если какой-то
        текст начнёт стрелять — тест укажет конкретный текст и тип, что упрощает
        отладку регрессии по сравнению с агрегированной метрикой выше.
        """
        for text in CLEAN_TEXTS:
            with self.subTest(text=text):
                types = sorted(_fired_types(text))
                self.assertEqual(
                    types,
                    [],
                    msg=f"Ожидали 0 находок, получили {types} на тексте {text!r}",
                )

    def test_redact_leaves_clean_text_unchanged(self):
        """Раз находок нет — ``redact`` не должен менять чистый текст."""
        for text in CLEAN_TEXTS:
            with self.subTest(text=text):
                result = redact(text)
                self.assertEqual(
                    result.masked_text,
                    text,
                    msg=f"redact изменил чистый текст: {result.masked_text!r}",
                )


class AcceptedFalsePositives(unittest.TestCase):
    """Документируем известные/принятые неоднозначности, не считая их регрессией."""

    def test_accepted_fp_four_part_version(self):
        """4-частная версия ``1.2.3.4`` БОЛЬШЕ НЕ ловится как IP.

        Раньше ``1.2.3.4`` было неотличимо от IPv4 и детектировалось как IP.
        После улучшения детектора (подавление version-context) версия в
        контексте ``build`` / ``версия`` корректно НЕ маскируется. Фиксируем
        это отдельно, чтобы регрессия детектора IP сразу была заметна.
        """
        text = "build 1.2.3.4 final"
        findings = scan(text)
        types = sorted({f.type for f in findings})
        # Версия в контексте сборки подавлена — никаких находок, в т.ч. IP.
        self.assertEqual(types, [])
        # И маскированный вывод не меняется: чистый текст остаётся как есть.
        self.assertEqual(redact(text).masked_text, text)

    def test_three_part_version_is_not_ip(self):
        """Контроль границы: 3-частная версия 1.2.3 НЕ должна ловиться как IP."""
        self.assertEqual(sorted({f.type for f in scan("ship 1.2.3 today")}), [])


if __name__ == "__main__":
    unittest.main()
