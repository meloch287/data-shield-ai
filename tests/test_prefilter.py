"""Тесты литерального пре-скрина RegexDetector (prefilter) и паритета детекции.

prefilter — дешёвый substring-предфильтр: если ни одного из литералов нет в
тексте, detect() сразу возвращает [] без запуска regex. Здесь проверяем:
  * detector с prefilter -> [] когда литерала нет, и нормально матчит когда есть;
  * prefilter принимает str и tuple (а также None);
  * detector БЕЗ prefilter работает как раньше (предфильтр не влияет);
  * паритет детекции: каждый тип секрета по-прежнему ловится scan() после
    появления prefilter — никаких ложных отрицаний на 15 позитивных входах.

Значения секретов собираем конкатенацией, чтобы не светить «настоящие» ключи.
Утверждаем ФАКТИЧЕСКОЕ поведение, наблюдаемое на исходниках проекта.
"""
from __future__ import annotations

import unittest

from datashield import scan
from datashield.detectors.base import Finding, RegexDetector

# Паттерны взяты дословно из datashield/detectors/*, чтобы тесты били по реальной
# семантике, а не по выдуманным регуляркам.
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
AWS_PATTERN = r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
ETH_PATTERN = r"\b0x[a-fA-F0-9]{40}\b"
TWILIO_PATTERN = r"\bAC[0-9a-fA-F]{32}\b"  # детектор twilio_sid — БЕЗ prefilter


def _email_detector(prefilter):
    return RegexDetector("email", "EMAIL", EMAIL_PATTERN, 0.98, prefilter=prefilter)


class PrefilterAbsentSkipsRegexTests(unittest.TestCase):
    """Когда литерала prefilter нет в тексте, detect() -> [] (regex не бежит)."""

    def test_email_without_at_returns_empty(self):
        det = _email_detector("@")
        # В тексте нет '@' — даже если бы там было что-то почти-email, пропускаем.
        self.assertEqual(det.detect("no email here, just words and a dot.com"), [])

    def test_email_with_at_detects_normally(self):
        det = _email_detector("@")
        text = "reach me at john.doe@example.com please"
        found = det.detect(text)
        self.assertEqual([f.value for f in found], ["john.doe@example.com"])
        self.assertIsInstance(found[0], Finding)
        self.assertEqual(found[0].type, "EMAIL")

    def test_prefilter_present_but_pattern_no_match_returns_empty(self):
        # '@' присутствует, но это не email — prefilter пропускает дальше, а
        # сам regex ничего не находит. Итог тот же — пустой список.
        det = _email_detector("@")
        self.assertEqual(det.detect("user @ host (with spaces) not an address"), [])


class PrefilterAcceptsStrTests(unittest.TestCase):
    """prefilter=str нормализуется в одноэлементный кортеж и работает."""

    def test_single_string_literal_skips_when_absent(self):
        det = RegexDetector("eth", "ETH", ETH_PATTERN, 0.95, prefilter="0x")
        self.assertEqual(det.detect("plain text without any hex address"), [])

    def test_single_string_literal_matches_when_present(self):
        det = RegexDetector("eth", "ETH", ETH_PATTERN, 0.95, prefilter="0x")
        addr = "0x" + "a" * 40
        found = det.detect("wallet " + addr + " here")
        self.assertEqual([f.value for f in found], [addr])

    def test_str_prefilter_stored_as_single_element_tuple(self):
        det = RegexDetector("eth", "ETH", ETH_PATTERN, 0.95, prefilter="0x")
        self.assertEqual(det._prefilter, ("0x",))


class PrefilterAcceptsTupleTests(unittest.TestCase):
    """prefilter=tuple: detect() бежит, если присутствует ХОТЯ БЫ один литерал."""

    def test_tuple_skips_when_no_literal_present(self):
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=("AKIA", "ASIA")
        )
        self.assertEqual(det.detect("nothing aws-shaped in this line"), [])

    def test_tuple_matches_via_first_literal(self):
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=("AKIA", "ASIA")
        )
        key = "AKIA" + "1234567890ABCDEF"
        self.assertEqual([f.value for f in det.detect("key=" + key)], [key])

    def test_tuple_matches_via_second_literal(self):
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=("AKIA", "ASIA")
        )
        key = "ASIA" + "ABCDEFGHIJ123456"
        self.assertEqual([f.value for f in det.detect("key=" + key)], [key])

    def test_tuple_prefilter_stored_as_tuple(self):
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=("AKIA", "ASIA")
        )
        self.assertEqual(det._prefilter, ("AKIA", "ASIA"))

    def test_list_prefilter_coerced_to_tuple(self):
        # Конструктор делает tuple(prefilter) для не-str итерируемого.
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=["AKIA", "ASIA"]
        )
        self.assertEqual(det._prefilter, ("AKIA", "ASIA"))
        key = "ASIA" + "ABCDEFGHIJ123456"
        self.assertEqual([f.value for f in det.detect(key)], [key])


class NoPrefilterUnaffectedTests(unittest.TestCase):
    """Детектор без prefilter ведёт себя как раньше — предфильтр его не трогает."""

    def test_none_prefilter_stored_as_empty_tuple(self):
        det = RegexDetector("tw", "TWILIO_SID", TWILIO_PATTERN, 0.9)
        self.assertEqual(det._prefilter, ())

    def test_no_prefilter_detects_match(self):
        det = RegexDetector("tw", "TWILIO_SID", TWILIO_PATTERN, 0.9)
        sid = "AC" + "a" * 32
        self.assertEqual([f.value for f in det.detect("sid " + sid)], [sid])

    def test_no_prefilter_returns_empty_on_non_match(self):
        # Без prefilter всё равно пусто, но потому что regex не совпал, а не из-за
        # предфильтра. Поведение идентично предыдущей версии детектора.
        det = RegexDetector("tw", "TWILIO_SID", TWILIO_PATTERN, 0.9)
        self.assertEqual(det.detect("no twilio sid present here"), [])


class PrefilterCaseSensitivityTests(unittest.TestCase):
    """prefilter регистрозависим (как и сами паттерны)."""

    def test_lowercase_does_not_satisfy_uppercase_prefilter(self):
        det = RegexDetector(
            "aws", "AWS_ACCESS_KEY", AWS_PATTERN, 0.97, prefilter=("AKIA", "ASIA")
        )
        # 'akia' в нижнем регистре — prefilter не находит литерал -> [].
        self.assertEqual(det.detect("akia" + "1234567890abcdef"), [])


class DetectionParityViaScanTests(unittest.TestCase):
    """Паритет детекции: каждый тип секрета всё ещё ловится scan() с prefilter.

    15 позитивных входов; ни одного ложного отрицания. Значения собраны
    конкатенацией. Проверяем по типу находки, наблюдаемому на реальном движке.
    """

    def _detected_types(self, text):
        return {f.type for f in scan(text)}

    def _assert_detected(self, text, expected_type):
        self.assertIn(
            expected_type,
            self._detected_types(text),
            msg="ложное отрицание: %r не дал %s" % (text, expected_type),
        )

    def test_email_detected(self):
        self._assert_detected("contact john.doe@example.com", "EMAIL")

    def test_aws_akia_detected(self):
        self._assert_detected("AKIA" + "1234567890ABCDEF", "AWS_ACCESS_KEY")

    def test_aws_asia_detected(self):
        self._assert_detected("ASIA" + "ABCDEFGHIJ123456", "AWS_ACCESS_KEY")

    def test_anthropic_key_detected(self):
        self._assert_detected("sk-ant-" + "a" * 30, "ANTHROPIC_KEY")

    def test_openai_key_detected(self):
        self._assert_detected("sk-" + "A" * 30, "OPENAI_KEY")

    def test_github_token_detected(self):
        self._assert_detected("ghp_" + "a" * 40, "GITHUB_TOKEN")

    def test_github_pat_detected(self):
        self._assert_detected("github_pat_" + "A" * 65, "GITHUB_TOKEN")

    def test_gitlab_token_detected(self):
        self._assert_detected("glpat-" + "a" * 25, "GITLAB_TOKEN")

    def test_jwt_detected(self):
        self._assert_detected("eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 20, "JWT")

    def test_private_key_block_detected(self):
        block = (
            "-----BEGIN PRIVATE KEY-----\n"
            + "MIIB" + "a" * 40 + "\n"
            + "-----END PRIVATE KEY-----"
        )
        self._assert_detected(block, "PRIVATE_KEY")

    def test_eth_address_detected(self):
        self._assert_detected("0x" + "a" * 40, "ETH_ADDRESS")

    def test_google_api_key_detected(self):
        self._assert_detected("AIza" + "0" * 35, "GOOGLE_API_KEY")

    def test_slack_token_detected(self):
        self._assert_detected("xoxb-" + "1" * 12, "SLACK_TOKEN")

    def test_stripe_key_detected(self):
        self._assert_detected("sk_live_" + "a" * 20, "STRIPE_KEY")

    def test_sendgrid_key_detected(self):
        self._assert_detected("SG." + "a" * 22 + "." + "b" * 43, "SENDGRID_KEY")

    def test_no_false_negatives_across_fifteen_positive_inputs(self):
        # Сводный чек: каждый из 15 входов даёт ожидаемый тип. Гарантирует,
        # что prefilter нигде не «съел» позитив (паттерны и литералы согласованы).
        cases = [
            ("contact john.doe@example.com", "EMAIL"),
            ("AKIA" + "1234567890ABCDEF", "AWS_ACCESS_KEY"),
            ("ASIA" + "ABCDEFGHIJ123456", "AWS_ACCESS_KEY"),
            ("sk-ant-" + "a" * 30, "ANTHROPIC_KEY"),
            ("sk-" + "A" * 30, "OPENAI_KEY"),
            ("ghp_" + "a" * 40, "GITHUB_TOKEN"),
            ("github_pat_" + "A" * 65, "GITHUB_TOKEN"),
            ("glpat-" + "a" * 25, "GITLAB_TOKEN"),
            ("eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 20, "JWT"),
            (
                "-----BEGIN PRIVATE KEY-----\n" + "MIIB" + "a" * 40
                + "\n-----END PRIVATE KEY-----",
                "PRIVATE_KEY",
            ),
            ("0x" + "a" * 40, "ETH_ADDRESS"),
            ("AIza" + "0" * 35, "GOOGLE_API_KEY"),
            ("xoxb-" + "1" * 12, "SLACK_TOKEN"),
            ("sk_live_" + "a" * 20, "STRIPE_KEY"),
            ("SG." + "a" * 22 + "." + "b" * 43, "SENDGRID_KEY"),
        ]
        self.assertEqual(len(cases), 15)
        for text, expected in cases:
            with self.subTest(expected=expected):
                self._assert_detected(text, expected)


class PrefilterEmailAbsenceSkipsViaScanTests(unittest.TestCase):
    """Через публичный scan(): отсутствие '@' означает отсутствие EMAIL."""

    def test_text_without_at_has_no_email(self):
        types = {f.type for f in scan("just an ordinary sentence with no address")}
        self.assertNotIn("EMAIL", types)

    def test_text_with_at_has_email(self):
        types = {f.type for f in scan("write to a.user@example.org now")}
        self.assertIn("EMAIL", types)


if __name__ == "__main__":
    unittest.main()
