"""Расширенные тесты CLI: новые типы (PERSON, ADDRESS, OGRN), фильтры,
--min-confidence, --report, --json для redact/scan/stats и команда detectors.

Запуск только этого модуля:
    python3 -m unittest tests.test_cli_advanced -v
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main

# Валидный ОГРН (13 знаков, контрольная цифра сходится): известный ОГРН Сбербанка.
OGRN_VALID = "1027700132195"


def run(argv, stdin_text=None):
    """Вызывает cli.main(argv) с подменой stdin и перехватом stdout/stderr."""
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


class RedactOnlyExcludeNewTypesTests(unittest.TestCase):
    """redact с --only / --exclude на новых типах PERSON, ADDRESS, OGRN."""

    # --- PERSON ---
    def test_only_person_masks_name_keeps_email(self):
        text = "меня зовут Иван Петров, почта a@b.com"
        code, out, _ = run(["redact", "--only", "PERSON"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn("[PERSON_1]", out)
        self.assertNotIn("Иван Петров", out)
        # EMAIL не входит в --only, поэтому остаётся как есть.
        self.assertIn("a@b.com", out)

    def test_only_person_lowercase_input_normalized(self):
        # _parse_types приводит к верхнему регистру — "person" работает.
        code, out, _ = run(["redact", "--only", "person"], stdin_text="меня зовут Иван Петров")
        self.assertEqual(code, 0)
        self.assertIn("[PERSON_1]", out)

    def test_exclude_person_keeps_name_masks_email(self):
        text = "меня зовут Иван Петров, почта a@b.com"
        code, out, _ = run(["redact", "--exclude", "PERSON"], stdin_text=text)
        self.assertEqual(code, 0)
        # PERSON исключён -> имя остаётся в открытом виде.
        self.assertIn("Иван Петров", out)
        # EMAIL по-прежнему маскируется.
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)

    def test_person_patronymic_triplet_masked(self):
        code, out, _ = run(["redact", "--only", "PERSON"], stdin_text="Иванов Иван Иванович подписал")
        self.assertEqual(code, 0)
        self.assertIn("[PERSON_1]", out)
        self.assertNotIn("Иванович", out)

    def test_person_english_title(self):
        code, out, _ = run(["redact", "--only", "PERSON"], stdin_text="Mr. John Smith arrived")
        self.assertEqual(code, 0)
        self.assertIn("[PERSON_1]", out)
        self.assertNotIn("John Smith", out)

    # --- ADDRESS ---
    def test_only_address_masks_street(self):
        text = "проживает по адресу ул. Ленина 5, телефон +7 999 123-45-67"
        code, out, _ = run(["redact", "--only", "ADDRESS"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn("[ADDRESS_1]", out)
        self.assertNotIn("Ленина", out)
        # PHONE_RU не в --only -> остаётся.
        self.assertIn("+7 999 123-45-67", out)

    def test_exclude_address_keeps_street(self):
        text = "адрес: проспект Мира 10, почта a@b.com"
        code, out, _ = run(["redact", "--exclude", "ADDRESS"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn("Мира", out)
        self.assertIn("[EMAIL_1]", out)

    # --- OGRN ---
    def test_only_ogrn_masks_valid_number(self):
        text = f"ОГРН {OGRN_VALID} компании, почта a@b.com"
        code, out, _ = run(["redact", "--only", "OGRN"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn("[OGRN_1]", out)
        self.assertNotIn(OGRN_VALID, out)
        # EMAIL вне --only.
        self.assertIn("a@b.com", out)

    def test_exclude_ogrn_keeps_number(self):
        text = f"ОГРН {OGRN_VALID}, e-mail a@b.com"
        code, out, _ = run(["redact", "--exclude", "OGRN"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn(OGRN_VALID, out)
        self.assertIn("[EMAIL_1]", out)

    def test_invalid_ogrn_not_masked(self):
        # 13 цифр, но контрольная цифра не сходится -> валидатор отклоняет.
        bad = "1027700132190"
        code, out, _ = run(["redact", "--only", "OGRN"], stdin_text="ОГРН " + bad)
        self.assertEqual(code, 0)
        self.assertNotIn("[OGRN_1]", out)
        self.assertIn(bad, out)

    def test_only_multiple_new_types(self):
        text = f"Иван Петров, ул. Ленина 5, ОГРН {OGRN_VALID}"
        code, out, _ = run(["redact", "--only", "PERSON,ADDRESS,OGRN"], stdin_text=text)
        self.assertEqual(code, 0)
        self.assertIn("[PERSON_1]", out)
        self.assertIn("[ADDRESS_1]", out)
        self.assertIn("[OGRN_1]", out)


class MinConfidenceTests(unittest.TestCase):
    """--min-confidence режет находки ниже порога."""

    def test_high_threshold_suppresses_address(self):
        # ADDRESS имеет уверенность 0.78; порог 0.8 её отсекает.
        code, out, err = run(
            ["scan", "--only", "ADDRESS", "--min-confidence", "0.8", "--json"],
            stdin_text="ул. Ленина 5, кв 3",
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), [])

    def test_low_threshold_keeps_address(self):
        code, out, _ = run(
            ["scan", "--only", "ADDRESS", "--min-confidence", "0.7", "--json"],
            stdin_text="ул. Ленина 5, кв 3",
        )
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertTrue(any(i["type"] == "ADDRESS" for i in items))

    def test_high_threshold_keeps_high_confidence_ogrn(self):
        # OGRN имеет уверенность 0.85 -> переживает порог 0.8.
        code, out, _ = run(
            ["scan", "--only", "OGRN", "--min-confidence", "0.8", "--json"],
            stdin_text="ОГРН " + OGRN_VALID,
        )
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertTrue(any(i["type"] == "OGRN" for i in items))

    def test_threshold_above_one_suppresses_everything(self):
        code, out, _ = run(
            ["scan", "--min-confidence", "1.1", "--json"],
            stdin_text="a@b.com меня зовут Иван Петров",
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), [])

    def test_redact_threshold_passthrough(self):
        # Слишком высокий порог -> текст не меняется.
        text = "ул. Ленина 5"
        code, out, _ = run(
            ["redact", "--only", "ADDRESS", "--min-confidence", "0.99"],
            stdin_text=text,
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, text)


class ReportTests(unittest.TestCase):
    """--report: JSON-аудит без сырых значений, с value_sha256."""

    def test_report_has_sha_and_no_raw_person(self):
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            code, _, _ = run(
                ["redact", "--report", report, "--only", "PERSON"],
                stdin_text="меня зовут Иван Петров",
            )
            self.assertEqual(code, 0)
            with open(report, encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(raw)
        # Структура отчёта.
        self.assertIn("salt", data)
        self.assertIn("entries", data)
        self.assertEqual(data["total"], 1)
        self.assertIn("value_sha256", raw)
        entry = data["entries"][0]
        self.assertEqual(entry["type"], "PERSON")
        self.assertIn("value_sha256", entry)
        # Сырое имя не должно попасть ни в один из ключей/значений отчёта.
        self.assertNotIn("Иван Петров", raw)
        self.assertNotIn("Петров", raw)

    def test_report_no_raw_ogrn(self):
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            run(
                ["redact", "--report", report, "--only", "OGRN"],
                stdin_text="ОГРН " + OGRN_VALID,
            )
            with open(report, encoding="utf-8") as f:
                raw = f.read()
        self.assertNotIn(OGRN_VALID, raw)
        self.assertIn("value_sha256", raw)

    def test_report_no_raw_address(self):
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            run(
                ["redact", "--report", report, "--only", "ADDRESS"],
                stdin_text="ул. Ленина 5",
            )
            with open(report, encoding="utf-8") as f:
                raw = f.read()
        # Название улицы не должно утечь в отчёт.
        self.assertNotIn("Ленина", raw)
        self.assertIn("value_sha256", raw)

    def test_report_entries_have_position_and_confidence(self):
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            run(
                ["redact", "--report", report, "--only", "PERSON"],
                stdin_text="меня зовут Иван Петров",
            )
            with open(report, encoding="utf-8") as f:
                data = json.load(f)
        entry = data["entries"][0]
        for key in ("type", "start", "end", "confidence", "detector", "value_sha256", "preview"):
            self.assertIn(key, entry)
        self.assertIsInstance(entry["start"], int)
        self.assertIsInstance(entry["end"], int)

    def test_report_and_stdout_both_produced(self):
        # --report пишет файл, а stdout всё равно содержит маскированный текст.
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            code, out, _ = run(
                ["redact", "--report", report, "--only", "PERSON"],
                stdin_text="меня зовут Иван Петров",
            )
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(report))
        self.assertIn("[PERSON_1]", out)


class JsonOutputTests(unittest.TestCase):
    """--json для redact / scan / stats."""

    def test_redact_json_structure_new_types(self):
        text = f"Иван Петров, ул. Ленина 5, ОГРН {OGRN_VALID}"
        code, out, _ = run(["redact", "--json"], stdin_text=text)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        for key in ("masked_text", "stats", "total", "placeholders"):
            self.assertIn(key, payload)
        self.assertEqual(payload["stats"].get("PERSON"), 1)
        self.assertEqual(payload["stats"].get("ADDRESS"), 1)
        self.assertEqual(payload["stats"].get("OGRN"), 1)
        # masked_text не содержит сырых значений.
        self.assertNotIn("Петров", payload["masked_text"])
        self.assertNotIn(OGRN_VALID, payload["masked_text"])
        # placeholders отображает плейсхолдер -> тип, без сырых значений.
        self.assertIn("[PERSON_1]", payload["placeholders"])
        self.assertEqual(payload["placeholders"]["[PERSON_1]"], "PERSON")

    def test_redact_json_total_matches_findings(self):
        code, out, _ = run(["redact", "--json"], stdin_text="a@b.com и c@d.com")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["stats"].get("EMAIL"), 2)

    def test_scan_json_fields_for_person(self):
        code, out, _ = run(["scan", "--json", "--only", "PERSON"], stdin_text="меня зовут Иван Петров")
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 1)
        item = items[0]
        for key in ("type", "start", "end", "confidence", "detector", "preview"):
            self.assertIn(key, item)
        self.assertEqual(item["type"], "PERSON")
        # scan показывает только превью, не сырое значение.
        self.assertNotIn("Иван Петров", item["preview"])

    def test_scan_json_empty_list_when_nothing(self):
        code, out, _ = run(["scan", "--json"], stdin_text="совершенно обычный текст")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), [])

    def test_scan_json_multiple_types(self):
        text = f"ОГРН {OGRN_VALID}, ул. Ленина 5"
        code, out, _ = run(["scan", "--json"], stdin_text=text)
        self.assertEqual(code, 0)
        kinds = {i["type"] for i in json.loads(out)}
        self.assertIn("OGRN", kinds)
        self.assertIn("ADDRESS", kinds)

    def test_stats_json_is_dict(self):
        code, out, _ = run(["stats", "--json"], stdin_text="a@b.com и c@d.com")
        self.assertEqual(code, 0)
        stats = json.loads(out)
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats.get("EMAIL"), 2)

    def test_stats_json_new_types(self):
        text = f"Иван Петров, ОГРН {OGRN_VALID}"
        code, out, _ = run(["stats", "--json"], stdin_text=text)
        self.assertEqual(code, 0)
        stats = json.loads(out)
        self.assertEqual(stats.get("PERSON"), 1)
        self.assertEqual(stats.get("OGRN"), 1)

    def test_stats_json_empty(self):
        code, out, _ = run(["stats", "--json"], stdin_text="нет данных")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {})


class DetectorsCommandTests(unittest.TestCase):
    """Команда detectors показывает новые детекторы и их статусы."""

    def test_lists_new_detectors(self):
        code, out, _ = run(["detectors"])
        self.assertEqual(code, 0)
        for name in ("names", "address_ru", "ogrn", "gliner"):
            self.assertIn(name, out)

    def test_new_detectors_have_correct_types(self):
        code, out, _ = run(["detectors"])
        self.assertEqual(code, 0)
        self.assertIn("PERSON", out)
        self.assertIn("ADDRESS", out)
        self.assertIn("OGRN", out)

    def test_default_on_detectors_marked_enabled(self):
        # names, address_ru, ogrn включены по умолчанию -> статус "вкл".
        code, out, _ = run(["detectors"])
        self.assertEqual(code, 0)
        for name in ("names", "address_ru", "ogrn"):
            # Строка вида "  [вкл ] <name>  -> TYPE"; имя стоит прямо перед "->".
            row = next(
                line for line in out.splitlines()
                if "->" in line and line.split("->")[0].split()[-1] == name
            )
            self.assertIn("вкл", row)

    def test_gliner_disabled_by_default(self):
        code, out, _ = run(["detectors"])
        row = next(line for line in out.splitlines() if "gliner" in line)
        self.assertIn("выкл", row)
        self.assertIn("по умолчанию выкл", row)

    def test_aggressive_names_disabled_by_default(self):
        code, out, _ = run(["detectors"])
        row = next(line for line in out.splitlines() if "names_aggressive" in line)
        self.assertIn("выкл", row)

    def test_detectors_config_enables_gliner(self):
        # Через конфиг можно включить gliner -> статус меняется на "вкл".
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, ".datashield.json")
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump({"enabled_detectors": ["gliner"]}, f)
            code, out, _ = run(["detectors", "--config", cfg])
        self.assertEqual(code, 0)
        row = next(line for line in out.splitlines() if "gliner" in line)
        self.assertIn("вкл", row)


class UnknownTypeTests(unittest.TestCase):
    """Неизвестный тип в --only / --exclude -> код возврата 2."""

    def test_unknown_only_returns_2(self):
        code, _, err = run(["redact", "--only", "DOES_NOT_EXIST"], stdin_text="a@b.com")
        self.assertEqual(code, 2)
        self.assertIn("Неизвестные типы", err)

    def test_unknown_only_lists_available(self):
        code, _, err = run(["redact", "--only", "ZZZ"], stdin_text="a@b.com")
        self.assertEqual(code, 2)
        # Сообщение перечисляет доступные типы, в т.ч. реально существующие.
        self.assertIn("Доступные типы", err)
        self.assertIn("PERSON", err)
        self.assertIn("OGRN", err)

    def test_unknown_exclude_returns_2(self):
        code, _, err = run(["redact", "--exclude", "FOO"], stdin_text="a@b.com")
        self.assertEqual(code, 2)
        self.assertIn("Неизвестные типы", err)

    def test_unknown_in_scan_returns_2(self):
        code, _, err = run(["scan", "--only", "BOGUS"], stdin_text="a@b.com")
        self.assertEqual(code, 2)
        self.assertIn("BOGUS", err)

    def test_mixed_known_unknown_returns_2(self):
        # Один валидный + один невалидный -> всё равно ошибка.
        code, _, err = run(["redact", "--only", "PERSON,NOPE"], stdin_text="меня зовут Иван Петров")
        self.assertEqual(code, 2)
        self.assertIn("NOPE", err)

    def test_known_types_succeed(self):
        # Контрольный позитив: только валидные типы -> код 0.
        code, _, _ = run(["redact", "--only", "PERSON,ADDRESS,OGRN"], stdin_text="меня зовут Иван Петров")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
