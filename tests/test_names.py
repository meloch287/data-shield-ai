"""Тесты детекции имён (PERSON): газеттир + эвристики, позитив и негатив.

Покрываем поведение datashield/detectors/names.py и газеттиров
datashield/data/names.py через публичный API (scan/redact/Config) и через
прямое использование NameDetector.

Ключевые инварианты, на которые опираются тесты:
  * Дефолтный детектор `names` даёт уверенность >= 0.8 на всех сигналах,
    поэтому при min_confidence=0.7 они все маскируются.
  * Агрессивный детектор `names_aggressive` (одиночные имена, 0.7) ВЫКЛЮЧЕН
    по умолчанию и включается через Config(enabled_detectors=("names_aggressive",)).
  * Слова-омонимы и просто заглавные слова (Москва, Россия, Привет) в дефолте
    не ловятся.
"""
import unittest

from datashield import Config, redact, scan
from datashield.data.names import (
    ALL_GIVEN_NAMES,
    EN_GIVEN_NAMES,
    RU_GIVEN_NAMES,
    is_given_name,
)
from datashield.detectors.names import NameDetector, build, build_optional


# Конфиг с включённым агрессивным режимом (одиночные имена).
AGGRESSIVE = Config(enabled_detectors=("names_aggressive",))


def types_in(text, **kwargs):
    return {f.type for f in scan(text, **kwargs)}


def values_in(text, **kwargs):
    return {f.value for f in scan(text, **kwargs)}


def detectors_in(text, **kwargs):
    return {f.detector for f in scan(text, **kwargs)}


# --------------------------------------------------------------------------- #
# Русские отчества
# --------------------------------------------------------------------------- #
class RussianPatronymicTests(unittest.TestCase):
    def test_patronymic_ovich(self):
        self.assertIn("PERSON", types_in("это сказал Иванович"))

    def test_patronymic_evich(self):
        self.assertIn("PERSON", types_in("пришёл Сергеевич"))

    def test_patronymic_ovna(self):
        self.assertIn("PERSON", types_in("позвонила Петровна"))

    def test_patronymic_evna(self):
        self.assertIn("PERSON", types_in("это Сергеевна"))

    def test_bare_ich_word_not_patronymic(self):
        # Одиночное слово на короткий «-ич» НЕ считается отчеством — иначе
        # ловятся нарицательные (Кирпич, Кулич, Москвич, Паралич).
        self.assertNotIn("PERSON", types_in("он Кузьмич родом из деревни"))
        self.assertNotIn("PERSON", types_in("Кирпич упал со стены"))
        self.assertNotIn("PERSON", types_in("вкусный Кулич на столе"))

    def test_ich_within_full_name_detected(self):
        # В составе «Имя Отчество» короткий «-ич» распознаётся (есть контекст).
        self.assertIn("PERSON", types_in("Пётр Ильич приехал"))

    def test_patronymic_inichna(self):
        # суффикс -инична из списка отчеств (например Кузьминична)
        self.assertIn("PERSON", types_in("приехала Кузьминична"))

    def test_lowercase_patronymic_not_matched(self):
        # отчество должно начинаться с заглавной буквы
        self.assertNotIn("PERSON", types_in("слово инична внутри предложения"))

    def test_patronymic_value_captured(self):
        self.assertIn("Анатольевич", values_in("уехал Анатольевич утром"))


# --------------------------------------------------------------------------- #
# Имя + Отчество и тройка ФИО
# --------------------------------------------------------------------------- #
class RussianNamePatronymicTests(unittest.TestCase):
    def test_name_and_patronymic(self):
        self.assertIn("Иван Иванович", values_in("Иван Иванович пришёл"))

    def test_name_patronymic_confidence(self):
        findings = scan("Иван Иванович пришёл")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.9)

    def test_name_patronymic_female(self):
        self.assertIn("Мария Сергеевна", values_in("Мария Сергеевна согласна"))


class RussianTripletTests(unittest.TestCase):
    def test_triplet_surname_first(self):
        # порядок: Фамилия Имя Отчество
        self.assertIn(
            "Иванов Иван Иванович", values_in("Иванов Иван Иванович пришёл")
        )

    def test_triplet_patronymic_last(self):
        # порядок: Имя Отчество Фамилия (отчество в середине — первая ветка)
        self.assertIn(
            "Иван Иванович Иванов", values_in("Иван Иванович Иванов выступил")
        )

    def test_triplet_high_confidence(self):
        findings = scan("Петров Пётр Петрович здесь")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.9)

    def test_triplet_masked_as_single_unit(self):
        result = redact("Иванов Иван Иванович пришёл")
        self.assertEqual(result.stats.get("PERSON"), 1)
        self.assertNotIn("Иванов", result.masked_text)
        self.assertNotIn("Иванович", result.masked_text)


# --------------------------------------------------------------------------- #
# Русский контекст ("меня зовут X", "господин X", "фамилия X" ...)
# --------------------------------------------------------------------------- #
class RussianContextTests(unittest.TestCase):
    def test_menya_zovut(self):
        self.assertIn("Алексей", values_in("меня зовут Алексей"))

    def test_zovut_substring(self):
        # триггер 'зовут' срабатывает и без 'меня'
        self.assertIn("PERSON", types_in("его зовут Дмитрий"))

    def test_gospodin(self):
        self.assertIn("Петров", values_in("господин Петров согласен"))

    def test_gospozha(self):
        self.assertIn("Смирнова", values_in("госпожа Смирнова ответила"))

    def test_familiya(self):
        self.assertIn("Сидоров", values_in("фамилия Сидоров записана"))

    def test_po_familii(self):
        self.assertIn("Кузнецов", values_in("по фамилии Кузнецов значится"))

    def test_uvazhaemy(self):
        self.assertIn("Сергей", values_in("уважаемый Сергей, добрый день"))

    def test_klient(self):
        self.assertIn("Смирнова", values_in("клиент Смирнова обратилась"))

    def test_patsient(self):
        self.assertIn("Орлов", values_in("пациент Орлов поступил утром"))

    def test_grazhdanin(self):
        self.assertIn("PERSON", types_in("гражданин Соколов задержан"))

    def test_context_confidence(self):
        findings = scan("господин Петров")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.85)

    def test_context_trigger_word_not_masked(self):
        # маскируется только имя, само слово-триггер остаётся
        result = redact("господин Петров")
        self.assertIn("господин", result.masked_text)
        self.assertNotIn("Петров", result.masked_text)


# --------------------------------------------------------------------------- #
# Газеттирные пары "Имя Фамилия" (RU)
# --------------------------------------------------------------------------- #
class RussianPairTests(unittest.TestCase):
    def test_known_given_plus_surname(self):
        self.assertIn("Иван Петров", values_in("Иван Петров приехал"))

    def test_pair_confidence(self):
        findings = scan("Иван Петров приехал")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.8)

    def test_female_given_plus_surname(self):
        self.assertIn("Мария Соколова", values_in("Мария Соколова выступила"))

    def test_pair_requires_known_first_word(self):
        # 'Петров' не в газеттире имён -> пара не ловится (нет одиночного в дефолте)
        self.assertNotIn("PERSON", types_in("Петров Иван написал"))

    def test_pair_requires_capital_second_word(self):
        # второе слово со строчной -> не пара, одиночное имя в дефолте не ловится
        self.assertNotIn("PERSON", types_in("Иван бежит домой"))


# --------------------------------------------------------------------------- #
# Английские титулы и контекст
# --------------------------------------------------------------------------- #
class EnglishTitleTests(unittest.TestCase):
    def test_mr_dot(self):
        self.assertIn("Smith", values_in("Mr. Smith arrived"))

    def test_mr_no_dot(self):
        self.assertIn("Brown", values_in("Mr Brown is here"))

    def test_dr(self):
        self.assertIn("Watson", values_in("Dr. Watson examined the patient"))

    def test_prof(self):
        self.assertIn("PERSON", types_in("Prof. Anna lectured today"))

    def test_mrs(self):
        self.assertIn("Davis", values_in("Mrs. Davis called back"))

    def test_title_two_words(self):
        self.assertIn("John Smith", values_in("Mr. John Smith called"))

    def test_title_confidence(self):
        findings = scan("Dr. Watson here")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.85)


class EnglishContextTests(unittest.TestCase):
    def test_my_name_is(self):
        self.assertIn("Robert", values_in("my name is Robert"))

    def test_i_am(self):
        self.assertIn("PERSON", types_in("I am Michael from sales"))

    def test_dear(self):
        self.assertIn("Jennifer", values_in("Dear Jennifer, thanks for"))

    def test_dear_two_words(self):
        self.assertIn("John Smith", values_in("Dear John Smith, please find"))

    def test_sincerely(self):
        self.assertIn("William", values_in("Sincerely, William"))

    def test_best_regards(self):
        self.assertIn("PERSON", types_in("Best regards, David"))

    def test_context_confidence(self):
        findings = scan("my name is Robert")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.85)


class EnglishPairTests(unittest.TestCase):
    def test_known_given_plus_surname(self):
        self.assertIn("John Smith", values_in("John Smith arrived early"))

    def test_pair_confidence(self):
        findings = scan("John Smith arrived")
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertGreaterEqual(person.confidence, 0.8)

    def test_female_given_plus_surname(self):
        self.assertIn("Mary Johnson", values_in("Mary Johnson reported it"))

    def test_pair_requires_known_first_word(self):
        # 'Random' не известное имя -> пара не ловится
        self.assertNotIn("PERSON", types_in("Random Words Here Today"))


# --------------------------------------------------------------------------- #
# НЕГАТИВ: обычные слова и омонимы не должны ловиться в дефолте
# --------------------------------------------------------------------------- #
class NegativeDefaultTests(unittest.TestCase):
    def test_cities_and_country_not_persons(self):
        self.assertNotIn("PERSON", types_in("Москва Россия Привет"))

    def test_single_moscow_not_person(self):
        self.assertNotIn("PERSON", types_in("Москва — столица"))

    def test_capitalized_pair_not_person(self):
        # пара заглавных, где первое не имя из газеттира
        self.assertNotIn("PERSON", types_in("Большой Театр открыт сегодня"))

    def test_bare_known_name_not_masked_by_default(self):
        # одиночное известное имя в дефолте НЕ маскируется (защита от омонимов)
        self.assertNotIn("PERSON", types_in("просто Иван здесь"))

    def test_bare_homonym_vera_not_masked(self):
        # 'Вера' — имя-омоним; в дефолте не ловится
        self.assertNotIn("PERSON", types_in("его вела вперёд Вера и сила"))

    def test_bare_english_name_not_masked(self):
        self.assertNotIn("PERSON", types_in("just Michael here"))

    def test_ordinary_english_words_not_persons(self):
        self.assertNotIn("PERSON", types_in("Hello World Today"))

    def test_redact_leaves_plain_text_untouched(self):
        result = redact("Москва Россия Привет")
        self.assertEqual(result.masked_text, "Москва Россия Привет")
        self.assertNotIn("PERSON", result.stats)


# --------------------------------------------------------------------------- #
# Агрессивный режим: одиночные известные имена
# --------------------------------------------------------------------------- #
class AggressiveModeTests(unittest.TestCase):
    def test_bare_ru_name_masked_when_enabled(self):
        self.assertIn("PERSON", types_in("просто Иван здесь", config=AGGRESSIVE))

    def test_bare_en_name_masked_when_enabled(self):
        self.assertIn("PERSON", types_in("just Michael here", config=AGGRESSIVE))

    def test_aggressive_detector_name(self):
        self.assertIn(
            "names_aggressive", detectors_in("просто Иван здесь", config=AGGRESSIVE)
        )

    def test_diminutive_masked_when_enabled(self):
        # уменьшительная форма из газеттира
        self.assertIn("Маша", values_in("там была Маша", config=AGGRESSIVE))

    def test_homonym_masked_when_enabled(self):
        # в агрессиве омонимы ловятся (это и есть его компромисс)
        self.assertIn("Вера", values_in("Вера и Любовь", config=AGGRESSIVE))

    def test_aggressive_confidence_is_07(self):
        findings = scan("просто Иван здесь", config=AGGRESSIVE)
        person = [f for f in findings if f.type == "PERSON"][0]
        self.assertAlmostEqual(person.confidence, 0.7, places=5)

    def test_aggressive_still_ignores_non_names(self):
        # даже в агрессиве слова не из газеттира не ловятся
        self.assertNotIn("PERSON", types_in("Москва Россия", config=AGGRESSIVE))

    def test_unknown_capitalized_word_not_masked_in_aggressive(self):
        self.assertNotIn("PERSON", types_in("просто Театр здесь", config=AGGRESSIVE))


# --------------------------------------------------------------------------- #
# Прямое использование NameDetector и газеттиров
# --------------------------------------------------------------------------- #
class DetectorWiringTests(unittest.TestCase):
    def test_default_detector_name(self):
        self.assertEqual(NameDetector().name, "names")

    def test_aggressive_detector_name(self):
        self.assertEqual(NameDetector(bare_only=True).name, "names_aggressive")

    def test_build_returns_default(self):
        built = build()
        self.assertEqual([d.name for d in built], ["names"])

    def test_build_optional_returns_aggressive(self):
        built = build_optional()
        self.assertEqual([d.name for d in built], ["names_aggressive"])

    def test_detector_type_is_person(self):
        self.assertEqual(NameDetector().type, "PERSON")

    def test_direct_detect_patronymic(self):
        d = NameDetector()
        findings = d.detect("это Иванович сказал")
        self.assertTrue(any(f.value == "Иванович" for f in findings))

    def test_direct_detect_pair_needs_known_first(self):
        d = NameDetector()
        # 'Петров' не в газеттире -> пара не ловится
        self.assertEqual(d.detect("Петров Иван"), [])

    def test_aggressive_detector_finds_single(self):
        d = NameDetector(bare_only=True)
        findings = d.detect("просто Иван здесь")
        self.assertTrue(any(f.value == "Иван" for f in findings))

    def test_default_detector_ignores_single(self):
        d = NameDetector()
        self.assertEqual(d.detect("просто Иван здесь"), [])


class GazetteerTests(unittest.TestCase):
    def test_ru_male_in_set(self):
        self.assertIn("иван", RU_GIVEN_NAMES)

    def test_ru_female_in_set(self):
        self.assertIn("мария", RU_GIVEN_NAMES)

    def test_ru_diminutive_in_set(self):
        self.assertIn("маша", RU_GIVEN_NAMES)

    def test_en_name_in_set(self):
        self.assertIn("john", EN_GIVEN_NAMES)

    def test_all_names_is_union(self):
        self.assertEqual(ALL_GIVEN_NAMES, RU_GIVEN_NAMES | EN_GIVEN_NAMES)

    def test_city_not_in_gazetteer(self):
        self.assertNotIn("москва", ALL_GIVEN_NAMES)

    def test_names_stored_lowercase(self):
        # все элементы в нижнем регистре
        self.assertTrue(all(name == name.lower() for name in RU_GIVEN_NAMES))

    def test_is_given_name_case_insensitive(self):
        self.assertTrue(is_given_name("Иван"))
        self.assertTrue(is_given_name("иван"))
        self.assertTrue(is_given_name("JOHN"))

    def test_is_given_name_rejects_non_name(self):
        self.assertFalse(is_given_name("Москва"))
        self.assertFalse(is_given_name("Театр"))


# --------------------------------------------------------------------------- #
# Сквозные сценарии redact()
# --------------------------------------------------------------------------- #
class RedactIntegrationTests(unittest.TestCase):
    def test_name_replaced_with_placeholder(self):
        result = redact("Иван Иванович пришёл")
        self.assertIn("[PERSON_1]", result.masked_text)
        self.assertNotIn("Иванович", result.masked_text)

    def test_same_name_stable_placeholder(self):
        result = redact("Иван Иванович и снова Иван Иванович")
        # одинаковое значение -> один и тот же плейсхолдер
        self.assertEqual(result.masked_text.count("[PERSON_1]"), 2)
        self.assertNotIn("[PERSON_2]", result.masked_text)

    def test_two_different_names_two_placeholders(self):
        result = redact("Mr. Smith and Dr. Watson")
        self.assertIn("[PERSON_1]", result.masked_text)
        self.assertIn("[PERSON_2]", result.masked_text)

    def test_mixed_ru_en_both_masked(self):
        text = "Иван Иванович writes to Mr. Smith"
        result = redact(text)
        self.assertNotIn("Иванович", result.masked_text)
        self.assertNotIn("Smith", result.masked_text)
        self.assertEqual(result.stats.get("PERSON"), 2)


if __name__ == "__main__":
    unittest.main()
