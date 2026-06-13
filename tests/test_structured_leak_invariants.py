"""Инвариант «нет утечки» для структурных форматов NDJSON и XML.

Главная гарантия приватного инструмента: после маскировки в выводе НЕ остаётся
ни одного исходного «сырого» чувствительного значения, а структура остаётся
машиночитаемой. Проверяется на собранном наборе значений:

- email (``[EMAIL_1]``);
- телефон РФ (``[PHONE_RU_1]``);
- банковская карта с валидной контрольной суммой Луна (``[CREDIT_CARD_1]``);
- ИНН (``[INN_1]``): 12-значный детектится сам по себе, 10-значный — по контексту
  «ИНН …»;
- секреты под чувствительным КЛЮЧОМ/ИМЕНЕМ узла (password/token) → ``[REDACTED]``;
- github-токен ``ghp_…`` детектится движком как ``[GITHUB_TOKEN_1]``.

Инварианты вывода:
- NDJSON: каждая строка, которая на входе была валидным JSON, снова парсится
  ``json.loads``; пустые строки сохраняются; невалидная JSON-строка превращается
  в замаскированный текст (никогда не выдаётся сырьём).
- XML: весь вывод снова парсится ``ET.fromstring``.

Значения подобраны по ФАКТИЧЕСКОМУ поведению движка (см. probes в истории
разработки): ИНН/карта/телефон/email проверены эмпирически. Тесты
детерминированы — без рандома и времени.

Только stdlib unittest.
"""
from __future__ import annotations

import json
import unittest
import xml.etree.ElementTree as ET

from datashield.api import build_engine
from datashield.structured import redact_format, redact_ndjson, redact_xml

_REDACTED = "[REDACTED]"

# --- собранный корпус значений ----------------------------------------------
# Каждая запись: (сырое_значение, ожидаемый_плейсхолдер_при_прогоне_через_движок).
# Плейсхолдеры выверены эмпирически на стандартном движке build_engine().
EMAIL = "alice@example.com"
PHONE_RU = "+7 916 123-45-67"
CARD_LUHN = "4539148803436467"   # валиден по Луну
INN12 = "500100732259"           # 12-значный ИНН, детектится без контекста
INN10 = "7707083893"             # 10-значный ИНН, детектится по контексту «ИНН …»
GITHUB_TOKEN = "ghp_AbCdEf0123456789AbCdEf0123456789abcd"
PASSWORD_VALUE = "hunter2SuperSecret"   # сам по себе движком НЕ детектится
TOKEN_VALUE = "qwerty-bare-token-value"  # сам по себе движком НЕ детектится

# Значения, прогоняемые через движок как текст значения, → конкретный плейсхолдер.
ENGINE_VALUE_EXPECT = {
    EMAIL: "[EMAIL_1]",
    PHONE_RU: "[PHONE_RU_1]",
    CARD_LUHN: "[CREDIT_CARD_1]",
    INN12: "[INN_1]",
    GITHUB_TOKEN: "[GITHUB_TOKEN_1]",
}

# Все сырые значения, которых НЕ должно остаться в выводе ни в одном тесте.
ALL_RAW_VALUES = [
    EMAIL,
    PHONE_RU,
    CARD_LUHN,
    INN12,
    INN10,
    GITHUB_TOKEN,
    PASSWORD_VALUE,
    TOKEN_VALUE,
]


def _luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class TestCorpusPreconditions(unittest.TestCase):
    """Самопроверка корпуса: значения и плейсхолдеры соответствуют движку."""

    def test_card_is_luhn_valid(self):
        # Карта в наборе действительно проходит контрольную сумму Луна.
        self.assertTrue(_luhn_ok(CARD_LUHN))

    def test_engine_placeholders_match_assumptions(self):
        # Каждое «детектируемое» значение даёт ожидаемый плейсхолдер
        # и не оставляет сырьё в результате прогона движком.
        eng = build_engine()
        for raw, placeholder in ENGINE_VALUE_EXPECT.items():
            masked = eng.redact(raw).masked_text
            self.assertEqual(masked, placeholder, f"для {raw!r}")
            self.assertNotIn(raw, masked)

    def test_inn10_needs_context_inn12_standalone(self):
        # ФАКТ: 10-значный ИНН детектится только с префиксом «ИНН …»,
        # 12-значный — и без контекста.
        eng = build_engine()
        self.assertEqual(eng.redact("ИНН " + INN10).masked_text, "ИНН [INN_1]")
        self.assertEqual(eng.redact(INN10).masked_text, INN10)  # bare 10-значный сырой
        self.assertEqual(eng.redact(INN12).masked_text, "[INN_1]")

    def test_bare_secret_values_not_detected_by_engine(self):
        # ФАКТ: «голые» пароль/токен без чувствительного ключа движком НЕ ловятся —
        # поэтому в no-leak тестах они кладутся под sensitive-ключ/имя узла.
        eng = build_engine()
        self.assertEqual(eng.redact(PASSWORD_VALUE).masked_text, PASSWORD_VALUE)
        self.assertEqual(eng.redact(TOKEN_VALUE).masked_text, TOKEN_VALUE)


class TestNdjsonLeakInvariant(unittest.TestCase):
    """NDJSON: нет утечки сырых значений + структура остаётся валидной."""

    def _build_ndjson(self) -> str:
        # Несколько объектов + пустая строка + одна невалидная JSON-строка.
        obj1 = {
            "email": EMAIL,
            "phone": PHONE_RU,
            "card": CARD_LUHN,
            "inn": INN12,
            "note": "ИНН " + INN10,           # 10-значный ИНН по контексту
            "password": PASSWORD_VALUE,        # sensitive-ключ → [REDACTED]
            "token": TOKEN_VALUE,              # sensitive-ключ → [REDACTED]
            "github": GITHUB_TOKEN,            # детектируется движком
        }
        obj2 = {
            "nested": {"secret": PASSWORD_VALUE, "ok": "plain"},
            "contacts": [EMAIL, PHONE_RU, 7, True, None],
        }
        invalid_line = f"plain text {EMAIL} {PHONE_RU} not-json"
        return "\n".join([
            json.dumps(obj1),
            "",                # пустая строка должна сохраниться
            invalid_line,      # невалидный JSON → маскируется как текст
            json.dumps(obj2),
        ])

    def test_no_raw_value_leaks(self):
        out = redact_ndjson(self._build_ndjson())
        for raw in ALL_RAW_VALUES:
            self.assertNotIn(raw, out, f"сырое значение просочилось: {raw!r}")

    def test_valid_json_lines_reparse(self):
        src = self._build_ndjson()
        src_lines = src.split("\n")
        out_lines = redact_ndjson(src).split("\n")
        # Покомпонентное соответствие: число строк сохранено.
        self.assertEqual(len(out_lines), len(src_lines))
        for src_line, out_line in zip(src_lines, out_lines):
            if not src_line.strip():
                # Пустая строка сохраняется как есть.
                self.assertEqual(out_line, src_line)
                continue
            try:
                json.loads(src_line)
            except ValueError:
                # Строка была невалидным JSON — на выходе это замаскированный текст,
                # не обязанный быть JSON; проверяем лишь отсутствие сырья.
                self.assertNotIn(EMAIL, out_line)
                self.assertNotIn(PHONE_RU, out_line)
                continue
            # Строка была валидным JSON — на выходе снова валидный JSON.
            json.loads(out_line)

    def test_sensitive_keys_become_redacted(self):
        out = redact_ndjson(self._build_ndjson())
        first = json.loads(out.split("\n")[0])
        self.assertEqual(first["password"], _REDACTED)
        self.assertEqual(first["token"], _REDACTED)
        # github-токен под несенситивным ключом → плейсхолдер движка, не сырьё.
        self.assertEqual(first["github"], "[GITHUB_TOKEN_1]")

    def test_detected_values_become_placeholders(self):
        out = redact_ndjson(self._build_ndjson())
        first = json.loads(out.split("\n")[0])
        self.assertEqual(first["email"], "[EMAIL_1]")
        self.assertEqual(first["phone"], "[PHONE_RU_1]")
        self.assertEqual(first["card"], "[CREDIT_CARD_1]")
        self.assertEqual(first["inn"], "[INN_1]")
        self.assertEqual(first["note"], "ИНН [INN_1]")

    def test_nested_and_scalar_structure_preserved(self):
        out = redact_ndjson(self._build_ndjson())
        second = json.loads(out.split("\n")[1 + 2])  # после пустой и невалидной строк
        self.assertEqual(second["nested"]["secret"], _REDACTED)
        self.assertEqual(second["nested"]["ok"], "plain")
        # Список: длина и нестроковые скаляры сохранены, PII заменены.
        self.assertEqual(second["contacts"], ["[EMAIL_1]", "[PHONE_RU_1]", 7, True, None])

    def test_invalid_json_line_is_masked_not_raw(self):
        out_lines = redact_ndjson(self._build_ndjson()).split("\n")
        invalid_out = out_lines[2]  # третья строка — бывший невалидный JSON
        self.assertIn("[EMAIL_1]", invalid_out)
        self.assertIn("[PHONE_RU_1]", invalid_out)
        self.assertNotIn(EMAIL, invalid_out)
        self.assertNotIn(PHONE_RU, invalid_out)

    def test_empty_and_blank_input(self):
        # Пустой ввод и ввод из одних пустых строк сохраняются как есть.
        self.assertEqual(redact_ndjson(""), "")
        self.assertEqual(redact_ndjson("\n\n"), "\n\n")

    def test_explicit_engine_argument(self):
        # Передача движка позиционно даёт тот же no-leak результат.
        eng = build_engine()
        src = self._build_ndjson()
        out = redact_ndjson(src, eng)
        for raw in ALL_RAW_VALUES:
            self.assertNotIn(raw, out)


class TestXmlLeakInvariant(unittest.TestCase):
    """XML: нет утечки сырых значений + вывод снова парсится ET.fromstring."""

    def _build_xml(self) -> str:
        # Карта в атрибуте id, секрет в атрибуте password (sensitive имя),
        # PII в тексте узлов, секрет в узле <token> (sensitive имя),
        # github-токен в несенситивном узле, комментарий с PII (должен отброситься).
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<user id="{CARD_LUHN}" password="{PASSWORD_VALUE}">'
            f"<email>{EMAIL}</email>"
            f"<phone>{PHONE_RU}</phone>"
            f"<card>{CARD_LUHN}</card>"
            f"<inn>{INN12}</inn>"
            f"<note>ИНН {INN10} contact {EMAIL}</note>"
            f"<token>{TOKEN_VALUE}</token>"
            f"<github>{GITHUB_TOKEN}</github>"
            f"<!-- secret comment {EMAIL} {PHONE_RU} -->"
            "</user>"
        )

    def test_no_raw_value_leaks(self):
        out = redact_xml(self._build_xml())
        for raw in ALL_RAW_VALUES:
            self.assertNotIn(raw, out, f"сырое значение просочилось: {raw!r}")

    def test_output_reparses(self):
        out = redact_xml(self._build_xml())
        root = ET.fromstring(out)  # не должно бросать
        self.assertEqual(root.tag, "user")

    def test_xml_declaration_preserved(self):
        out = redact_xml(self._build_xml())
        self.assertTrue(out.lstrip().startswith("<?xml"))

    def test_node_text_and_attrs_redacted(self):
        out = redact_xml(self._build_xml())
        root = ET.fromstring(out)
        # PII-текст узлов → плейсхолдеры.
        self.assertEqual(root.find("email").text, "[EMAIL_1]")
        self.assertEqual(root.find("phone").text, "[PHONE_RU_1]")
        self.assertEqual(root.find("card").text, "[CREDIT_CARD_1]")
        self.assertEqual(root.find("inn").text, "[INN_1]")
        self.assertEqual(root.find("note").text, "ИНН [INN_1] contact [EMAIL_1]")
        self.assertEqual(root.find("github").text, "[GITHUB_TOKEN_1]")
        # Карта в атрибуте id → плейсхолдер движка.
        self.assertEqual(root.get("id"), "[CREDIT_CARD_1]")

    def test_sensitive_node_and_attr_name_become_redacted(self):
        out = redact_xml(self._build_xml())
        root = ET.fromstring(out)
        # Узел <token> и атрибут password — sensitive по ИМЕНИ → целиком [REDACTED].
        self.assertEqual(root.find("token").text, _REDACTED)
        self.assertEqual(root.get("password"), _REDACTED)

    def test_comment_dropped(self):
        out = redact_xml(self._build_xml())
        # Комментарий отброшен: ни маркера, ни его PII в выводе нет.
        self.assertNotIn("<!--", out)
        self.assertNotIn("secret comment", out)

    def test_doctype_rejected(self):
        # DOCTYPE → ValueError (защита от entity-expansion).
        with self.assertRaises(ValueError):
            redact_xml(f'<!DOCTYPE x><user><email>{EMAIL}</email></user>')

    def test_entity_declaration_rejected(self):
        with self.assertRaises(ValueError):
            redact_xml(
                '<!ENTITY lol "lol"><user>x</user>'
            )

    def test_malformed_xml_raises_value_error(self):
        # Незакрытый/несогласованный тег → ValueError (а не сырьё наружу).
        with self.assertRaises(ValueError):
            redact_xml(f"<user><email>{EMAIL}</user>")

    def test_namespaced_sensitive_local_name(self):
        # Sensitive-имя определяется по ЛОКАЛЬНОМУ имени (без namespace).
        src = (
            '<root xmlns:s="urn:secret">'
            f"<s:password>{PASSWORD_VALUE}</s:password>"
            f"<s:email>{EMAIL}</s:email>"
            "</root>"
        )
        out = redact_xml(src)
        root = ET.fromstring(out)
        # Локальное имя 'password' → sensitive, текст узла целиком [REDACTED].
        pw = [el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "password"][0]
        self.assertEqual(pw.text, _REDACTED)
        em = [el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "email"][0]
        self.assertEqual(em.text, "[EMAIL_1]")
        self.assertNotIn(PASSWORD_VALUE, out)
        self.assertNotIn(EMAIL, out)

    def test_explicit_engine_argument(self):
        eng = build_engine()
        out = redact_xml(self._build_xml(), eng)
        for raw in ALL_RAW_VALUES:
            self.assertNotIn(raw, out)


class TestRedactFormatDispatcher(unittest.TestCase):
    """redact_format: диспетчер сохраняет no-leak инвариант для ndjson/xml."""

    def test_ndjson_via_dispatcher(self):
        src = json.dumps({"email": EMAIL, "password": PASSWORD_VALUE})
        out = redact_format(src, "ndjson")
        self.assertNotIn(EMAIL, out)
        self.assertNotIn(PASSWORD_VALUE, out)
        parsed = json.loads(out)
        self.assertEqual(parsed["email"], "[EMAIL_1]")
        self.assertEqual(parsed["password"], _REDACTED)

    def test_xml_via_dispatcher(self):
        src = f"<user><email>{EMAIL}</email><password>{PASSWORD_VALUE}</password></user>"
        out = redact_format(src, "xml")
        self.assertNotIn(EMAIL, out)
        self.assertNotIn(PASSWORD_VALUE, out)
        ET.fromstring(out)  # снова парсится

    def test_unknown_format_raises_value_error(self):
        with self.assertRaises(ValueError):
            redact_format("{}", "yaml")


if __name__ == "__main__":
    unittest.main()
