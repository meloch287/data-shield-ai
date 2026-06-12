"""Тесты детектора адресов РФ (datashield/detectors/addresses.py).

Покрывает два детектора, которые собирает addresses.build():
  * address_ru   → тип ADDRESS  (якорь на тип улицы + название)
  * postal_code_ru → тип POSTAL_CODE (6 цифр, только рядом со словом «индекс»)

Проверяем фактическое поведение: позитивные кейсы по каждому типу улицы,
негативные (просто текст, индекс без ключевого слова), а также тонкости
регулярки — обрезку названия по запятой/точке-с-запятой/40 символам,
требование пробела после ключевого слова, окно контекста индекса.
"""
import unittest

from datashield import redact, scan
from datashield.detectors import addresses


def types_in(text, **kwargs):
    """Множество типов находок в тексте (через публичный scan)."""
    return {f.type for f in scan(text, **kwargs)}


def findings_of(text, type_, **kwargs):
    """Список находок заданного типа."""
    return [f for f in scan(text, **kwargs) if f.type == type_]


class AddressPositiveTests(unittest.TestCase):
    """Каждый поддерживаемый тип улицы должен давать ADDRESS."""

    def test_ul_abbrev(self):
        self.assertIn("ADDRESS", types_in("живу на ул. Ленина дом 5"))

    def test_ulitsa_full(self):
        self.assertIn("ADDRESS", types_in("улица Пушкина расположена тут"))

    def test_ulitsa_declension_ulitse(self):
        # «улиц[аеыу]» — поддержаны падежные формы.
        self.assertIn("ADDRESS", types_in("встретимся на улице Гоголя сегодня"))

    def test_prospekt_full(self):
        self.assertIn("ADDRESS", types_in("проспект Мира 100 корпус 2"))

    def test_prospekt_abbrev_prosp(self):
        self.assertIn("ADDRESS", types_in("офис на просп. Ленинградский"))

    def test_prospekt_abbrev_prkt(self):
        self.assertIn("ADDRESS", types_in("дом на пр-кт Вернадского"))

    def test_pereulok_full(self):
        self.assertIn("ADDRESS", types_in("переулок Тихий за углом"))

    def test_pereulok_abbrev(self):
        self.assertIn("ADDRESS", types_in("свернуть в пер. Кривой направо"))

    def test_shosse_full(self):
        self.assertIn("ADDRESS", types_in("шоссе Энтузиастов забито"))

    def test_shosse_abbrev(self):
        self.assertIn("ADDRESS", types_in("ехать по ш. Космонавтов"))

    def test_naberezhnaya_full(self):
        self.assertIn("ADDRESS", types_in("набережная Фонтанки красивая"))

    def test_naberezhnaya_abbrev(self):
        self.assertIn("ADDRESS", types_in("гуляли по наб. Мойки вечером"))

    def test_bulvar_full(self):
        self.assertIn("ADDRESS", types_in("бульвар Гагарина широкий"))

    def test_bulvar_abbrev(self):
        self.assertIn("ADDRESS", types_in("дом на бул. Роз стоит"))

    def test_ploschad_full(self):
        self.assertIn("ADDRESS", types_in("площадь Революции в центре"))

    def test_ploschad_abbrev(self):
        self.assertIn("ADDRESS", types_in("митинг на пл. Восстания"))

    def test_proezd(self):
        self.assertIn("ADDRESS", types_in("проезд Серебрякова рядом"))

    def test_case_insensitive_upper(self):
        # Ключевое слово — регистронезависимо (?i:...).
        self.assertIn("ADDRESS", types_in("УЛ. ЛЕНИНА дом 1"))

    def test_case_insensitive_capitalized(self):
        self.assertIn("ADDRESS", types_in("Улица Пушкина рядом"))

    def test_confidence_is_078(self):
        found = findings_of("ул. Ленина дом 5", "ADDRESS")
        self.assertEqual(len(found), 1)
        self.assertAlmostEqual(found[0].confidence, 0.78, places=3)

    def test_detector_name(self):
        found = findings_of("проспект Мира", "ADDRESS")
        self.assertEqual(found[0].detector, "address_ru")


class AddressCaptureTests(unittest.TestCase):
    """Что именно захватывается как значение ADDRESS."""

    def test_value_includes_keyword(self):
        # Значение начинается с самого типа улицы.
        found = findings_of("улица Пушкина рядом", "ADDRESS")
        self.assertTrue(found[0].value.startswith("улица"))

    def test_capture_stops_at_comma(self):
        # Захват ограничен запятой: «дом 10» после запятой не попадает.
        found = findings_of("улица Пушкина, дом 10", "ADDRESS")
        self.assertEqual(found[0].value, "улица Пушкина")

    def test_capture_stops_at_semicolon(self):
        found = findings_of("ул. Тверская; офис 3", "ADDRESS")
        self.assertEqual(found[0].value, "ул. Тверская")

    def test_capture_stops_at_newline(self):
        # Перевод строки тоже граница (паттерн [^\n,;]).
        found = findings_of("ул. Арбат\nследующая строка", "ADDRESS")
        self.assertEqual(found[0].value, "ул. Арбат")

    def test_capture_truncated_at_40_chars(self):
        # После «ул. » берётся максимум 40 символов названия.
        tail = "Y" * 60
        found = findings_of("ул. " + tail, "ADDRESS")
        # «ул. » (4 символа) + 40 «Y» = 44 символа.
        self.assertEqual(len(found[0].value), 44)
        self.assertEqual(found[0].value, "ул. " + "Y" * 40)

    def test_span_matches_value(self):
        found = findings_of("ул. Ленина", "ADDRESS")
        f = found[0]
        self.assertEqual(f.end - f.start, len(f.value))


class AddressNegativeTests(unittest.TestCase):
    """Ситуации, где ADDRESS появляться не должен."""

    def test_plain_text_no_address(self):
        self.assertNotIn("ADDRESS", types_in("Просто текст без улиц и адресов."))

    def test_unrelated_sentence(self):
        self.assertNotIn(
            "ADDRESS",
            types_in("Сегодня хорошая погода и настроение отличное."),
        )

    def test_no_space_after_dot(self):
        # Регулярка требует \s+ после ключевого слова: «ул.Ленина» без пробела
        # не матчится.
        self.assertNotIn("ADDRESS", types_in("ул.Ленина дом 5"))

    def test_keyword_only_no_name(self):
        # Одно ключевое слово без названия (нет пробела+текста) — не адрес.
        self.assertNotIn("ADDRESS", types_in("улица"))

    def test_name_too_short_one_char(self):
        # Минимум 2 символа после пробела: «ул. А» (1 символ) не проходит.
        self.assertNotIn("ADDRESS", types_in("ул. А"))

    def test_name_two_chars_ok(self):
        # А вот 2 символа уже достаточно — это позитивный контроль к предыдущему.
        self.assertIn("ADDRESS", types_in("ул. Ав"))

    def test_prkt_requires_kt(self):
        # Паттерн «пр-?кт» требует «кт»: «пр-т» (без к) адресом не считается.
        self.assertNotIn("ADDRESS", types_in("пр-т Мира дом 1"))

    def test_word_proezdom_not_substring_anchor(self):
        # «проезд» как тип улицы требует пробел+название; здесь его нет —
        # просто отдельное слово без последующего пробела с именем.
        self.assertNotIn("ADDRESS", types_in("проезд"))


class AddressMultipleTests(unittest.TestCase):
    """Несколько адресов / взаимодействие с другими данными."""

    def test_two_streets_in_run_merge_into_one_match(self):
        # Между «и» нет запятой, поэтому жадный [^\n,;]{2,40} захватывает всё
        # одним матчем — но тип всё равно ADDRESS присутствует.
        found = findings_of("ул. Ленина и проспект Мира", "ADDRESS")
        self.assertTrue(any(f.value.startswith("ул.") for f in found))

    def test_two_streets_separated_by_comma(self):
        # Запятая разрывает захват — должно получиться два отдельных адреса.
        found = findings_of("ул. Ленина, проспект Мира", "ADDRESS")
        self.assertEqual(len(found), 2)
        values = {f.value for f in found}
        self.assertIn("ул. Ленина", values)
        self.assertIn("проспект Мира", values)


class PostalCodePositiveTests(unittest.TestCase):
    """Индекс ловится только при слове «индекс» рядом (контекст слева)."""

    def test_postal_with_keyword(self):
        self.assertIn("POSTAL_CODE", types_in("индекс 101000 верный"))

    def test_postal_with_keyword_colon(self):
        self.assertIn("POSTAL_CODE", types_in("Почтовый индекс: 190000"))

    def test_postal_keyword_with_words_between(self):
        # «индекс получателя 630099» — ключевое слово в пределах окна (25 симв.).
        self.assertIn("POSTAL_CODE", types_in("индекс получателя 630099 ок"))

    def test_postal_confidence_boosted(self):
        found = findings_of("индекс 101000", "POSTAL_CODE")
        self.assertEqual(len(found), 1)
        self.assertAlmostEqual(found[0].confidence, 0.85, places=3)

    def test_postal_value_is_six_digits(self):
        found = findings_of("индекс 630099", "POSTAL_CODE")
        self.assertEqual(found[0].value, "630099")

    def test_postal_detector_name(self):
        found = findings_of("индекс 101000", "POSTAL_CODE")
        self.assertEqual(found[0].detector, "postal_code_ru")

    def test_postal_keyword_case_insensitive(self):
        # keyword компилируется с re.IGNORECASE.
        self.assertIn("POSTAL_CODE", types_in("ИНДЕКС 101000 указан"))


class PostalCodeNegativeTests(unittest.TestCase):
    """Без слова «индекс» рядом 6 цифр не должны становиться POSTAL_CODE."""

    def test_six_digits_without_keyword(self):
        # base_confidence=0.3 < min_confidence 0.7 → отфильтровано.
        self.assertNotIn("POSTAL_CODE", types_in("число 101000 в файле"))

    def test_plain_number_no_postal(self):
        self.assertNotIn("POSTAL_CODE", types_in("в отчёте 630099 строк"))

    def test_five_digits_not_postal(self):
        # Ровно 6 цифр требуется; 5 — нет.
        self.assertNotIn("POSTAL_CODE", types_in("индекс 12345 короткий"))

    def test_seven_digits_not_postal(self):
        # 7 цифр подряд не дают 6-значного матча (lookaround по обеим сторонам).
        self.assertNotIn("POSTAL_CODE", types_in("индекс 1234567 длинный"))

    def test_keyword_after_number_does_not_boost(self):
        # Контекст берётся ТОЛЬКО слева от числа; «индекс» после числа не
        # поднимает уверенность, значение остаётся ниже порога.
        self.assertNotIn("POSTAL_CODE", types_in("630099 это индекс"))

    def test_keyword_too_far_does_not_boost(self):
        # Окно контекста — 25 символов слева. Если «индекс» дальше — нет буста.
        text = "индекс этого почтового отделения весьма далеко 630099 тут"
        self.assertNotIn("POSTAL_CODE", types_in(text))

    def test_window_boundary_inside_boosts(self):
        # Полное «индекс» помещается в окно [start-25, start) → буст есть.
        text = "индекс" + " " * 19 + "123456"  # число начинается на позиции 25
        self.assertIn("POSTAL_CODE", types_in(text))

    def test_window_boundary_outside_no_boost(self):
        # «индекс» выезжает за окно → буста нет, число отфильтровано.
        text = "индекс" + " " * 25 + "123456"
        self.assertNotIn("POSTAL_CODE", types_in(text))


class PostalCodeLowConfidenceTests(unittest.TestCase):
    """При сниженном пороге base-уверенность индекса видна явно."""

    def test_base_confidence_visible_with_low_threshold(self):
        # Без ключевого слова base=0.3 — видно только при min_confidence<=0.3.
        found = findings_of(
            "номер 654321 здесь", "POSTAL_CODE", min_confidence=0.0
        )
        self.assertEqual(len(found), 1)
        self.assertAlmostEqual(found[0].confidence, 0.3, places=3)


class AddressRedactTests(unittest.TestCase):
    """Сквозная маскировка через redact()."""

    def test_redact_address_placeholder(self):
        result = redact("живу на ул. Ленина")
        self.assertIn("ADDRESS", result.stats)
        self.assertNotIn("ул. Ленина", result.masked_text)
        self.assertIn("[ADDRESS_1]", result.masked_text)

    def test_redact_address_and_postal(self):
        result = redact("ул. Ленина, индекс 101000")
        self.assertEqual(result.stats.get("ADDRESS"), 1)
        self.assertEqual(result.stats.get("POSTAL_CODE"), 1)
        self.assertIn("[ADDRESS_1]", result.masked_text)
        self.assertIn("[POSTAL_CODE_1]", result.masked_text)
        self.assertNotIn("101000", result.masked_text)

    def test_redact_plain_text_unchanged(self):
        text = "Просто текст без адресов."
        result = redact(text)
        self.assertEqual(result.masked_text, text)
        self.assertNotIn("ADDRESS", result.stats)

    def test_only_address_filter(self):
        # only=ADDRESS оставляет только адрес, индекс отбрасывается.
        found = types_in("ул. Ленина индекс 101000", only=["ADDRESS"])
        self.assertEqual(found, {"ADDRESS"})

    def test_exclude_address_filter(self):
        # exclude=ADDRESS убирает адрес.
        self.assertNotIn("ADDRESS", types_in("ул. Ленина", exclude=["ADDRESS"]))


class AddressBuildTests(unittest.TestCase):
    """Прямая проверка фабрики addresses.build()."""

    def test_build_returns_two_detectors(self):
        built = addresses.build()
        self.assertEqual(len(built), 2)

    def test_build_detector_types(self):
        types = {d.type for d in addresses.build()}
        self.assertEqual(types, {"ADDRESS", "POSTAL_CODE"})

    def test_build_detector_names(self):
        names = {d.name for d in addresses.build()}
        self.assertEqual(names, {"address_ru", "postal_code_ru"})

    def test_address_detector_detect_directly(self):
        # Детектор работает изолированно, без движка.
        det = next(d for d in addresses.build() if d.type == "ADDRESS")
        found = det.detect("ул. Ленина дом 5")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].type, "ADDRESS")

    def test_postal_detector_detect_directly_boosted(self):
        det = next(d for d in addresses.build() if d.type == "POSTAL_CODE")
        found = det.detect("индекс 101000")
        self.assertEqual(len(found), 1)
        self.assertAlmostEqual(found[0].confidence, 0.85, places=3)

    def test_postal_detector_detect_directly_base(self):
        # Без ключевого слова детектор возвращает находку, но с base=0.3
        # (фильтрация по порогу — забота движка, не детектора).
        det = next(d for d in addresses.build() if d.type == "POSTAL_CODE")
        found = det.detect("число 101000")
        self.assertEqual(len(found), 1)
        self.assertAlmostEqual(found[0].confidence, 0.3, places=3)


if __name__ == "__main__":
    unittest.main()
