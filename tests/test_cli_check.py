"""Тесты команды CLI `datashield check` (CI/pre-commit gate).

Поведение, проверяемое здесь, подтверждено по реальному источнику
``datashield/cli.py::_cmd_check`` и эмпирически:

* код возврата 1, если в тексте найдены конфиденциальные данные, иначе 0;
* для каждого находки печатается ``path: [TYPE] category/severity preview``
  в stdout, при этом сырое значение НЕ выводится (только ``mask_preview``);
* итоговая строка-счётчик пишется в stderr;
* ``--min-severity`` отсеивает типы ниже порога (IP в одиночку — network/low —
  при ``--min-severity high`` даёт код 0);
* несколько файловых аргументов агрегируются;
* при отсутствии аргументов или ``-`` читается stdin.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main


def run(argv, stdin_text=None):
    """Запускает CLI, перехватывая stdout/stderr и (опц.) подменяя stdin."""
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


class CheckExitCodeTests(unittest.TestCase):
    def test_clean_text_exits_zero(self):
        code, out, err = run(["check", "-"], stdin_text="просто обычные слова тут")
        self.assertEqual(code, 0)
        # Никакого счётчика в stderr, когда ничего не найдено.
        self.assertEqual(err, "")

    def test_pii_present_exits_one(self):
        code, _out, _err = run(["check", "-"], stdin_text="пиши на a@b.com")
        self.assertEqual(code, 1)

    def test_finding_line_has_type_category_and_severity(self):
        code, out, _err = run(["check", "-"], stdin_text="пиши на a@b.com")
        self.assertEqual(code, 1)
        # Формат: "path: [TYPE] category/severity preview"
        self.assertIn("[EMAIL]", out)
        self.assertIn("contact/medium", out)

    def test_preview_never_leaks_raw_value(self):
        # mask_preview(value, visible=1): "a@b.com" -> "a******".
        code, out, _err = run(["check", "-"], stdin_text="секрет a@b.com внутри")
        self.assertEqual(code, 1)
        self.assertNotIn("a@b.com", out)
        self.assertIn("a******", out)

    def test_summary_counter_written_to_stderr(self):
        code, out, err = run(["check", "-"], stdin_text="карта 4111 1111 1111 1111")
        self.assertEqual(code, 1)
        # Счётчик-итог идёт в stderr, а не в stdout.
        self.assertIn("Найдено конфиденциальных данных: 1", err)
        self.assertNotIn("Найдено конфиденциальных данных", out)


class CheckMinSeverityTests(unittest.TestCase):
    def test_ip_alone_fails_without_filter(self):
        # IP относится к категории network/low — без фильтра это находка.
        code, out, _err = run(["check", "-"], stdin_text="сервер на 192.168.1.1")
        self.assertEqual(code, 1)
        self.assertIn("[IP]", out)
        self.assertIn("network/low", out)

    def test_ip_alone_ignored_with_min_severity_high(self):
        # network/low ниже high -> отфильтровано -> код 0, пустой вывод.
        code, out, err = run(
            ["check", "-", "--min-severity", "high"],
            stdin_text="сервер на 192.168.1.1",
        )
        self.assertEqual(code, 0)
        self.assertNotIn("[IP]", out)
        self.assertEqual(err, "")

    def test_high_severity_finding_still_fails_with_min_severity_high(self):
        # CREDIT_CARD — financial/critical, выше порога high -> по-прежнему падает.
        code, out, _err = run(
            ["check", "-", "--min-severity", "high"],
            stdin_text="карта 4111 1111 1111 1111",
        )
        self.assertEqual(code, 1)
        self.assertIn("[CREDIT_CARD]", out)
        self.assertIn("financial/critical", out)


class CheckFileArgsTests(unittest.TestCase):
    def test_single_file_with_pii(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("пиши на a@b.com")
            code, out, _err = run(["check", path])
            self.assertEqual(code, 1)
            # Имя файла появляется как префикс строки находки.
            self.assertIn(path, out)
            self.assertIn("[EMAIL]", out)

    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "clean.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("здесь нет персональных данных")
            code, out, err = run(["check", path])
            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            self.assertEqual(err, "")

    def test_multiple_files_aggregate(self):
        with tempfile.TemporaryDirectory() as d:
            p1 = os.path.join(d, "f1.txt")
            p2 = os.path.join(d, "f2.txt")
            with open(p1, "w", encoding="utf-8") as f:
                f.write("email a@b.com")
            with open(p2, "w", encoding="utf-8") as f:
                f.write("card 4111 1111 1111 1111")
            code, out, err = run(["check", p1, p2])
            self.assertEqual(code, 1)
            # Обе находки в выводе, каждая со своим путём-префиксом.
            self.assertIn(p1, out)
            self.assertIn(p2, out)
            self.assertIn("[EMAIL]", out)
            self.assertIn("[CREDIT_CARD]", out)
            # Счётчик агрегирован по обоим файлам.
            self.assertIn("Найдено конфиденциальных данных: 2", err)

    def test_aggregate_only_dirty_file_fails(self):
        with tempfile.TemporaryDirectory() as d:
            clean = os.path.join(d, "clean.txt")
            dirty = os.path.join(d, "dirty.txt")
            with open(clean, "w", encoding="utf-8") as f:
                f.write("ничего интересного")
            with open(dirty, "w", encoding="utf-8") as f:
                f.write("пиши на a@b.com")
            code, out, err = run(["check", clean, dirty])
            self.assertEqual(code, 1)
            self.assertIn(dirty, out)
            self.assertNotIn(clean, out)
            self.assertIn("Найдено конфиденциальных данных: 1", err)


class CheckStdinDefaultTests(unittest.TestCase):
    def test_no_args_reads_stdin(self):
        # Без файловых аргументов команда читает stdin (path == "-").
        code, out, _err = run(["check"], stdin_text="пиши на a@b.com")
        self.assertEqual(code, 1)
        self.assertIn("-:", out)
        self.assertIn("[EMAIL]", out)

    def test_dash_reads_stdin(self):
        code, out, _err = run(["check", "-"], stdin_text="пиши на a@b.com")
        self.assertEqual(code, 1)
        self.assertIn("-:", out)

    def test_no_args_clean_stdin_exits_zero(self):
        code, out, err = run(["check"], stdin_text="ничего секретного")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
