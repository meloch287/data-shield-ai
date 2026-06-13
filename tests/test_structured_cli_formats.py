"""Тесты CLI-команды ``redact --format`` для структурных форматов.

Покрываем диспетчеризацию ``--format ndjson|xml|json-data|csv`` через
``datashield.structured.redact_format``: успешный код 0, корректную маскировку,
отсутствие утечки сырья, а также обработку невалидного входа (ненулевой код и
сообщение в stderr). Часть проверок — через ``main([...])`` с временными файлами
``--in/--out``, часть — сквозь реальный subprocess ``python3 -m datashield``.

Тесты детерминированы: фиксированный вход, без рандома и времени.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import build_parser, main


def run(argv, stdin_text=None):
    """Запустить ``main(argv)`` в процессе, перехватив stdout/stderr/код."""
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


def run_files(argv_prefix, text):
    """Записать ``text`` во временный ``--in``, прогнать ``main``, вернуть выход.

    Возвращает ``(code, masked_output, stderr)`` где ``masked_output`` —
    содержимое файла ``--out``.
    """
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.dat")
        dst = os.path.join(d, "out.dat")
        with open(src, "w", encoding="utf-8") as f:
            f.write(text)
        code, out, err = run(list(argv_prefix) + ["--in", src, "--out", dst])
        masked = ""
        if os.path.exists(dst):
            with open(dst, encoding="utf-8") as f:
                masked = f.read()
        return code, masked, err


class FormatChoicesTests(unittest.TestCase):
    """Параметр --format должен предлагать ndjson и xml среди вариантов."""

    def _format_action(self):
        parser = build_parser()
        for sub in parser._subparsers._group_actions:
            redact = sub.choices.get("redact")
            if redact is None:
                continue
            for action in redact._actions:
                if action.dest == "format":
                    return action
        self.fail("не нашли действие --format у подкоманды redact")

    def test_choices_include_all_structured_formats(self):
        choices = self._format_action().choices
        for fmt in ("text", "json-data", "ndjson", "csv", "xml"):
            self.assertIn(fmt, choices)

    def test_choices_explicitly_have_ndjson_and_xml(self):
        choices = self._format_action().choices
        self.assertIn("ndjson", choices)
        self.assertIn("xml", choices)

    def test_default_format_is_text(self):
        self.assertEqual(self._format_action().default, "text")


class NdjsonFormatTests(unittest.TestCase):
    NDJSON = (
        '{"email": "a@b.com", "password": "hunter2"}\n'
        "\n"
        '{"phone": "+7 999 123-45-67"}\n'
    )

    def test_stdin_success_and_masked(self):
        code, out, err = run(["redact", "--format", "ndjson"], stdin_text=self.NDJSON)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        # значение под чувствительным ключом маскируется целиком
        self.assertIn("[REDACTED]", out)

    def test_no_raw_leak(self):
        _, out, _ = run(["redact", "--format", "ndjson"], stdin_text=self.NDJSON)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("hunter2", out)

    def test_blank_lines_preserved(self):
        # Между объектами есть пустая строка — она сохраняется как есть.
        _, out, _ = run(["redact", "--format", "ndjson"], stdin_text=self.NDJSON)
        self.assertEqual(out.count("\n"), self.NDJSON.count("\n"))
        lines = out.split("\n")
        self.assertEqual(lines[1], "")

    def test_invalid_json_line_masked_as_text_not_error(self):
        # Невалидная JSON-строка не валит команду: она маскируется как текст.
        code, out, err = run(
            ["redact", "--format", "ndjson"],
            stdin_text="это не json, но тут есть a@b.com",
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)

    def test_compact_json_output(self):
        # json.dumps без отступов: одна строка на объект, ключи через ", ".
        _, out, _ = run(
            ["redact", "--format", "ndjson"],
            stdin_text='{"email": "a@b.com", "password": "x"}',
        )
        self.assertEqual(out, '{"email": "[EMAIL_1]", "password": "[REDACTED]"}')

    def test_in_out_files(self):
        code, masked, err = run_files(["redact", "--format", "ndjson"], self.NDJSON)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[REDACTED]", masked)
        self.assertNotIn("a@b.com", masked)


class XmlFormatTests(unittest.TestCase):
    XML = (
        '<?xml version="1.0"?>'
        "<root>"
        "<email>a@b.com</email>"
        "<password>hunter2</password>"
        '<user id="x@y.com" token="abc">hi</user>'
        "</root>"
    )

    def test_stdin_success_and_masked(self):
        code, out, err = run(["redact", "--format", "xml"], stdin_text=self.XML)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        # чувствительные имя-тег и имя-атрибут → целиком [REDACTED]
        self.assertIn("<password>[REDACTED]</password>", out)
        self.assertIn('token="[REDACTED]"', out)

    def test_no_raw_leak(self):
        _, out, _ = run(["redact", "--format", "xml"], stdin_text=self.XML)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("x@y.com", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn('token="abc"', out)

    def test_xml_declaration_preserved(self):
        _, out, _ = run(["redact", "--format", "xml"], stdin_text=self.XML)
        self.assertTrue(out.lstrip().startswith("<?xml"))

    def test_invalid_xml_nonzero_exit_with_stderr(self):
        code, out, err = run(
            ["redact", "--format", "xml"],
            stdin_text="<root><unclosed></root>",
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("xml", err)
        self.assertIn("Некорректный XML", err)

    def test_doctype_rejected_nonzero_exit(self):
        code, out, err = run(
            ["redact", "--format", "xml"],
            stdin_text='<?xml version="1.0"?><!DOCTYPE x><root>a@b.com</root>',
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("entity-expansion", err)
        # сырьё не утекает даже при ошибке
        self.assertNotIn("a@b.com", out)

    def test_in_out_files(self):
        code, masked, err = run_files(["redact", "--format", "xml"], self.XML)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[REDACTED]", masked)
        self.assertNotIn("a@b.com", masked)


class JsonDataFormatTests(unittest.TestCase):
    JSON = '{"email": "a@b.com", "password": "hunter2", "nested": {"ssn": "1"}}'

    def test_stdin_success_and_masked(self):
        code, out, err = run(["redact", "--format", "json-data"], stdin_text=self.JSON)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[REDACTED]", out)

    def test_no_raw_leak(self):
        _, out, _ = run(["redact", "--format", "json-data"], stdin_text=self.JSON)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("hunter2", out)

    def test_pretty_printed_with_indent(self):
        # redact_json по умолчанию indent=2 → многострочный вывод.
        _, out, _ = run(["redact", "--format", "json-data"], stdin_text=self.JSON)
        self.assertIn("\n", out)
        self.assertIn('  "email": "[EMAIL_1]"', out)

    def test_invalid_json_nonzero_exit_with_stderr(self):
        code, out, err = run(
            ["redact", "--format", "json-data"],
            stdin_text="{ не валидный json",
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("json-data", err)

    def test_in_out_files(self):
        code, masked, err = run_files(["redact", "--format", "json-data"], self.JSON)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", masked)
        self.assertNotIn("a@b.com", masked)


class CsvFormatTests(unittest.TestCase):
    CSV = "name,email,password\nBob,a@b.com,hunter2\n"

    def test_stdin_success_and_masked(self):
        code, out, err = run(["redact", "--format", "csv"], stdin_text=self.CSV)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        # колонка password чувствительна по заголовку → целиком [REDACTED]
        self.assertIn("[REDACTED]", out)

    def test_no_raw_leak(self):
        _, out, _ = run(["redact", "--format", "csv"], stdin_text=self.CSV)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("hunter2", out)

    def test_header_row_preserved(self):
        _, out, _ = run(["redact", "--format", "csv"], stdin_text=self.CSV)
        self.assertTrue(out.startswith("name,email,password"))

    def test_in_out_files(self):
        code, masked, err = run_files(["redact", "--format", "csv"], self.CSV)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[REDACTED]", masked)
        self.assertNotIn("a@b.com", masked)


class UnknownFormatTests(unittest.TestCase):
    def test_unknown_format_rejected_by_argparse(self):
        # argparse отклоняет неизвестный choice → SystemExit(2) + сообщение.
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            main(["redact", "--format", "yaml"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("invalid choice", err.getvalue())


class SubprocessEndToEndTests(unittest.TestCase):
    """Сквозная проверка через реальный процесс ``python3 -m datashield``."""

    REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _run(self, argv, stdin_text):
        env = dict(os.environ)
        # Гарантируем, что подпроцесс находит пакет из корня репозитория.
        env["PYTHONPATH"] = (
            self.REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        )
        proc = subprocess.run(
            [sys.executable, "-m", "datashield", *argv],
            input=stdin_text,
            capture_output=True,
            text=True,
            cwd=self.REPO_ROOT,
            env=env,
            timeout=60,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_ndjson_exit_zero_and_masked(self):
        code, out, err = self._run(
            ["redact", "--format", "ndjson"],
            '{"email": "a@b.com", "password": "x"}\n',
        )
        self.assertEqual(code, 0, err)
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[REDACTED]", out)
        self.assertNotIn("a@b.com", out)

    def test_xml_exit_zero_and_masked(self):
        code, out, err = self._run(
            ["redact", "--format", "xml"],
            "<root><email>a@b.com</email></root>",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)

    def test_invalid_xml_nonzero_exit_and_stderr(self):
        code, out, err = self._run(
            ["redact", "--format", "xml"],
            "<root><oops></root>",
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("xml", err)

    def test_unknown_format_nonzero_exit(self):
        code, out, err = self._run(["redact", "--format", "nope"], "x")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)


if __name__ == "__main__":
    unittest.main()
