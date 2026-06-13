"""Block L — новые secret-детекторы: STRIPE_WEBHOOK, VAULT_TOKEN,
DOPPLER_TOKEN, PLANETSCALE_TOKEN, LINEAR_TOKEN.

Все секреты строятся КОНКАТЕНАЦией (префикс + тело), чтобы тело файла не
содержало «живых» ключей и не триггерило сканеры секретов на самом тесте.

Проверяем фактическое поведение реальных источников:
  * каждый секрет детектируется (изолированным детектором и полным движком);
  * паритет пре-фильтра: detect() идентичен со включённым и выключенным
    пре-фильтром — пре-фильтр НЕ должен ронять ни одной находки;
  * короткое замыкание: при отсутствии литерала-префикса дорогой regex не
    запускается, результат — пустой (но и сам паттерн всё равно бы не совпал);
  * таксономия: каждый тип -> категория "secret", критичность "critical";
  * compliance: regulations_for(тип) -> [] (секреты не регулируются);
  * каталог: 90 детекторов / 86 default-on / 83 типа — но числа вычисляются
    динамически из build_catalog, НЕ захардкожены (фиксируем только сам факт
    регистрации новых типов и их default-on статус).

Запуск:
    cd /Users/meloch287/Desktop/data-shield-ai && \
        python3 -m unittest tests.test_world_secrets -v
"""
from __future__ import annotations

import copy
import unittest

from datashield.api import build_engine
from datashield.compliance import regulations_for
from datashield.config import Config
from datashield.detectors import secrets as secrets_module
from datashield.detectors.base import RegexDetector
from datashield.detectors.registry import build_active, build_catalog
from datashield.taxonomy import category_of, severity_of

# Новые secret-типы блока L.
NEW_SECRET_TYPES = (
    "STRIPE_WEBHOOK",
    "VAULT_TOKEN",
    "DOPPLER_TOKEN",
    "PLANETSCALE_TOKEN",
    "LINEAR_TOKEN",
)


def _samples():
    """(имя_детектора, тип, валидное_значение, ожидаемый_префилтр).

    Значения строятся конкатенацией префикса и тела минимально-допустимой длины.
    Длины тел подтверждены прямым прогоном реальных детекторов:
      whsec_  + >=32   ;  hvs. + >=24   ;  dp.(st|pt|ct). + >=40
      pscale_(pw|tkn)_ + >=32   ;  lin_api_ + >=40
    """
    return [
        (
            "stripe_webhook", "STRIPE_WEBHOOK",
            "whsec_" + "A" * 32, ("whsec_",),
        ),
        (
            "hashicorp_vault", "VAULT_TOKEN",
            "hvs." + "B" * 24, ("hvs.",),
        ),
        (
            "doppler_token", "DOPPLER_TOKEN",
            "dp.st." + "C" * 40, ("dp.",),
        ),
        (
            "planetscale_token", "PLANETSCALE_TOKEN",
            "pscale_pw_" + "F" * 32, ("pscale_",),
        ),
        (
            "linear_token", "LINEAR_TOKEN",
            "lin_api_" + "H" * 40, ("lin_api_",),
        ),
    ]


def _by_name():
    return {d.name: d for d in secrets_module.build()}


class NewSecretDetectionTest(unittest.TestCase):
    """Каждый новый секрет детектируется изолированным детектором."""

    def test_each_secret_detected_isolated(self):
        by_name = _by_name()
        for name, type_, value, _pf in _samples():
            with self.subTest(detector=name):
                det = by_name[name]
                findings = det.detect("token " + value + " here")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].type, type_)
                # Матч покрывает весь секрет целиком (group=0).
                self.assertEqual(findings[0].value, value)

    def test_doppler_all_three_variants(self):
        # dp.st. / dp.pt. / dp.ct. — все три тела допустимы.
        det = _by_name()["doppler_token"]
        for kind in ("st", "pt", "ct"):
            with self.subTest(variant=kind):
                value = "dp." + kind + "." + "C" * 40
                findings = det.detect("export DOPPLER=" + value)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].type, "DOPPLER_TOKEN")
                self.assertEqual(findings[0].value, value)

    def test_planetscale_pw_and_tkn(self):
        # pscale_pw_ и pscale_tkn_ — обе формы.
        det = _by_name()["planetscale_token"]
        for body in ("pw", "tkn"):
            with self.subTest(form=body):
                value = "pscale_" + body + "_" + "F" * 32
                findings = det.detect("DB=" + value)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].type, "PLANETSCALE_TOKEN")


class FullEngineDetectionTest(unittest.TestCase):
    """Новые секреты детектируются дефолтным движком (default-on)."""

    @classmethod
    def setUpClass(cls):
        cls.engine = build_engine()

    def _types(self, text):
        return sorted({f.type for f in self.engine.analyze(text)})

    def test_each_secret_via_engine(self):
        for _name, type_, value, _pf in _samples():
            with self.subTest(type=type_):
                self.assertEqual(self._types("secret=" + value), [type_])

    def test_secret_is_masked_in_redaction(self):
        # Значение секрета не должно остаться в открытом виде после редакции.
        for _name, type_, value, _pf in _samples():
            with self.subTest(type=type_):
                result = self.engine.redact("config " + value + " end")
                self.assertNotIn(value, result.masked_text)
                self.assertIn(type_, result.stats)

    def test_clean_text_yields_no_new_secret(self):
        # Текст без секретов не порождает новых secret-находок.
        clean = "Just a plain sentence about webhooks and tokens, nothing real."
        found = set(self._types(clean))
        self.assertEqual(found & set(NEW_SECRET_TYPES), set())


class PrefilterParityTest(unittest.TestCase):
    """Пре-фильтр не теряет находок и корректно короткозамыкает."""

    def test_prefilter_literals_as_expected(self):
        by_name = _by_name()
        for name, _type, _value, expected_pf in _samples():
            with self.subTest(detector=name):
                self.assertEqual(by_name[name]._prefilter, expected_pf)

    def test_prefilter_drops_nothing(self):
        # Ключевой паритет: detect() идентичен с пре-фильтром и без него.
        by_name = _by_name()
        for name, _type, value, _pf in _samples():
            det = by_name[name]
            text = "leading text " + value + " trailing"
            twin = copy.copy(det)
            twin._prefilter = ()  # отключаем пре-фильтр на копии
            with self.subTest(detector=name):
                self.assertEqual(
                    [(f.type, f.start, f.end, f.value) for f in det.detect(text)],
                    [(f.type, f.start, f.end, f.value) for f in twin.detect(text)],
                )

    def test_prefilter_short_circuits_when_literal_absent(self):
        # Префикса нет в тексте -> detect() == [] (дорогой regex пропущен).
        by_name = _by_name()
        no_literal = "plain text with digits 1234567890 and words only"
        for name, _type, _value, pf in _samples():
            with self.subTest(detector=name):
                for literal in pf:
                    self.assertNotIn(literal, no_literal)
                self.assertEqual(by_name[name].detect(no_literal), [])

    def test_doppler_prefix_present_but_invalid_body(self):
        # 'dp.' есть, но вариант не st|pt|ct -> regex не матчит; паритет сохранён.
        det = _by_name()["doppler_token"]
        text = "value dp.zz." + "C" * 40 + " and dp.config=true"
        twin = copy.copy(det)
        twin._prefilter = ()
        self.assertEqual(det.detect(text), [])
        self.assertEqual(
            [(f.type, f.start) for f in det.detect(text)],
            [(f.type, f.start) for f in twin.detect(text)],
        )

    def test_below_minimum_length_not_matched(self):
        # Тело короче минимума -> не находка (фиксирует нижнюю границу длины).
        by_name = _by_name()
        too_short = {
            "stripe_webhook": "whsec_" + "A" * 31,
            "hashicorp_vault": "hvs." + "B" * 23,
            "doppler_token": "dp.st." + "C" * 39,
            "planetscale_token": "pscale_pw_" + "F" * 31,
            "linear_token": "lin_api_" + "H" * 39,
        }
        for name, value in too_short.items():
            with self.subTest(detector=name):
                self.assertEqual(by_name[name].detect("x " + value + " y"), [])


class TaxonomyAndComplianceTest(unittest.TestCase):
    """Каждый новый тип -> категория secret/critical, регламентов нет."""

    def test_category_is_secret(self):
        for type_ in NEW_SECRET_TYPES:
            with self.subTest(type=type_):
                self.assertEqual(category_of(type_), "secret")

    def test_severity_is_critical(self):
        for type_ in NEW_SECRET_TYPES:
            with self.subTest(type=type_):
                self.assertEqual(severity_of(type_), "critical")

    def test_regulations_empty(self):
        # Секреты не привязаны к регуляторным режимам: regulations_for -> [].
        for type_ in NEW_SECRET_TYPES:
            with self.subTest(type=type_):
                self.assertEqual(regulations_for(type_), [])

    def test_contrast_regulated_type_is_not_empty(self):
        # Контраст: контактный тип (EMAIL) регулируется — пустого списка не даёт.
        # Подтверждает, что [] у секретов — содержательный результат, а не баг
        # самого regulations_for.
        self.assertNotEqual(regulations_for("EMAIL"), [])


class CatalogRegistrationTest(unittest.TestCase):
    """Новые детекторы зарегистрированы и активны; счётчики — динамические."""

    @classmethod
    def setUpClass(cls):
        cls.catalog = build_catalog(Config())
        cls.active_types = {d.type for d in build_active(Config())}

    def test_new_detectors_in_catalog(self):
        names_in_catalog = {info.detector.name for info in self.catalog}
        for name, _type, _value, _pf in _samples():
            with self.subTest(detector=name):
                self.assertIn(name, names_in_catalog)

    def test_new_detectors_default_enabled_and_active(self):
        by_name = {info.detector.name: info for info in self.catalog}
        for name, type_, _value, _pf in _samples():
            with self.subTest(detector=name):
                info = by_name[name]
                self.assertTrue(info.default_enabled)
                self.assertTrue(info.enabled)
                self.assertIn(type_, self.active_types)

    def test_new_secret_types_present(self):
        catalog_types = {info.detector.type for info in self.catalog}
        for type_ in NEW_SECRET_TYPES:
            with self.subTest(type=type_):
                self.assertIn(type_, catalog_types)

    def test_counts_consistent_dynamically(self):
        # Числа НЕ захардкожены: вычисляем из каталога и сверяем внутреннюю
        # согласованность (default-on <= всего; типов <= детекторов).
        total = len(self.catalog)
        default_on = sum(1 for info in self.catalog if info.default_enabled)
        type_count = len({info.detector.type for info in self.catalog})
        self.assertGreater(total, 0)
        self.assertLessEqual(default_on, total)
        self.assertLessEqual(type_count, total)
        # Активных типов ровно столько же, сколько уникальных типов в каталоге
        # (все типы блока L default-on, ни одного отключённого по умолчанию типа,
        # которого нет среди включённых).
        self.assertEqual(type_count, len(self.active_types))

    def test_new_detectors_are_regex_with_prefilter(self):
        by_name = {info.detector.name: info.detector for info in self.catalog}
        for name, _type, _value, expected_pf in _samples():
            with self.subTest(detector=name):
                det = by_name[name]
                self.assertIsInstance(det, RegexDetector)
                self.assertEqual(det._prefilter, expected_pf)


if __name__ == "__main__":
    unittest.main()
