"""Тесты CLI для потоковой (redact --stream) и пакетной (batch) редакции.

Проверяет фактическое поведение datashield.cli.main(argv):
  - redact --stream с --in и --out маскирует файл и печатает число находок в stderr;
  - --stream без --in или без --out -> код 2 с сообщением;
  - batch --out-dir создаёт замаскированные файлы (суффикс по умолчанию .masked)
    и печатает счётчики по файлам;
  - --suffix и --workers учитываются.

Только stdlib unittest. ProcessPool-ветка использует top-level picklable
redact_one и небольшое число воркеров на реальных tempfile.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main


def run(argv, stdin_text=None):
    """Запускает main(argv), перехватывая stdout/stderr. Возвращает (code, out, err)."""
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


# Литералы, которые конкатенируем, чтобы исходник теста не содержал «секрета»
# целиком. Это обычный email — не настоящий ключ, но соблюдаем правило сборки
# чувствительных значений по частям.
_EMAIL = "alice" + "@" + "example.com"


class RedactStreamCliTests(unittest.TestCase):
    def test_stream_masks_file_and_prints_count_to_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.txt")
            dst = os.path.join(d, "out.txt")
            # 3 строки, по 2 одинаковых email в каждой -> 6 находок.
            line = "почта " + _EMAIL + " и " + _EMAIL + "\n"
            with open(src, "w", encoding="utf-8") as f:
                f.write(line * 3)

            code, out, err = run(["redact", "--stream", "--in", src, "--out", dst])

            self.assertEqual(code, 0)
            # Счётчик находок печатается в stderr (не в stdout).
            self.assertEqual(out, "")
            self.assertIn("находок: 6", err)

            with open(dst, encoding="utf-8") as f:
                masked = f.read()
            # Оригинальное значение замаскировано, плейсхолдер присутствует.
            self.assertNotIn(_EMAIL, masked)
            self.assertIn("[EMAIL_1]", masked)
            # Структура строк сохранена (3 строки).
            self.assertEqual(masked.count("\n"), 3)

    def test_stream_zero_findings(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "clean.txt")
            dst = os.path.join(d, "clean.out")
            with open(src, "w", encoding="utf-8") as f:
                f.write("здесь нет ничего секретного\nвторая строка\n")

            code, out, err = run(["redact", "--stream", "--in", src, "--out", dst])

            self.assertEqual(code, 0)
            self.assertIn("находок: 0", err)
            with open(dst, encoding="utf-8") as f:
                self.assertEqual(f.read(), "здесь нет ничего секретного\nвторая строка\n")

    def test_stream_without_out_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("почта " + _EMAIL + "\n")

            code, out, err = run(["redact", "--stream", "--in", src])

            self.assertEqual(code, 2)
            self.assertIn("--in", err)
            self.assertIn("--out", err)

    def test_stream_without_in_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            dst = os.path.join(d, "out.txt")

            code, out, err = run(["redact", "--stream", "--out", dst])

            self.assertEqual(code, 2)
            self.assertIn("--in", err)
            self.assertIn("--out", err)
            # Выходной файл не должен быть создан при ошибке использования.
            self.assertFalse(os.path.exists(dst))

    def test_stream_neither_in_nor_out_exits_2(self):
        code, out, err = run(["redact", "--stream"])
        self.assertEqual(code, 2)
        self.assertIn("--in", err)
        self.assertIn("--out", err)


class BatchCliTests(unittest.TestCase):
    def test_batch_creates_masked_files_default_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.txt")
            b = os.path.join(d, "b.txt")
            with open(a, "w", encoding="utf-8") as f:
                f.write("почта " + _EMAIL + "\n")
            with open(b, "w", encoding="utf-8") as f:
                f.write("здесь чисто\n")
            out_dir = os.path.join(d, "out")

            # workers=1 -> последовательная ветка (без ProcessPool).
            code, out, err = run(
                ["batch", a, b, "--out-dir", out_dir, "--workers", "1"]
            )

            self.assertEqual(code, 0)
            produced = sorted(os.listdir(out_dir))
            self.assertEqual(produced, ["a.txt.masked", "b.txt.masked"])

            masked_a = os.path.join(out_dir, "a.txt.masked")
            with open(masked_a, encoding="utf-8") as f:
                content_a = f.read()
            self.assertNotIn(_EMAIL, content_a)
            self.assertIn("[EMAIL_1]", content_a)

            masked_b = os.path.join(out_dir, "b.txt.masked")
            with open(masked_b, encoding="utf-8") as f:
                self.assertEqual(f.read(), "здесь чисто\n")

            # Per-file счётчики печатаются в stdout: путь -> число находок.
            self.assertIn("a.txt.masked: 1", out)
            self.assertIn("b.txt.masked: 0", out)

    def test_batch_honors_custom_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.txt")
            with open(a, "w", encoding="utf-8") as f:
                f.write("почта " + _EMAIL + "\n")
            out_dir = os.path.join(d, "out")

            code, out, err = run(
                ["batch", a, "--out-dir", out_dir, "--suffix", ".red", "--workers", "1"]
            )

            self.assertEqual(code, 0)
            self.assertEqual(sorted(os.listdir(out_dir)), ["a.txt.red"])
            self.assertIn("a.txt.red: 1", out)

    def test_batch_creates_out_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.txt")
            with open(a, "w", encoding="utf-8") as f:
                f.write("почта " + _EMAIL + "\n")
            # Несуществующий вложенный каталог должен быть создан.
            out_dir = os.path.join(d, "nested", "out")
            self.assertFalse(os.path.exists(out_dir))

            code, out, err = run(["batch", a, "--out-dir", out_dir, "--workers", "1"])

            self.assertEqual(code, 0)
            self.assertTrue(os.path.isdir(out_dir))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "a.txt.masked")))

    def test_batch_parallel_workers_processpool(self):
        # Ветка ProcessPool: несколько файлов и workers>1. Используем реальные
        # tempfile и top-level picklable redact_one (через CLI). Небольшое число
        # воркеров (2) и небольшое число файлов (3).
        with tempfile.TemporaryDirectory() as d:
            files = []
            for i in range(3):
                p = os.path.join(d, "f%d.txt" % i)
                with open(p, "w", encoding="utf-8") as f:
                    f.write("почта " + _EMAIL + "\n")
                files.append(p)
            out_dir = os.path.join(d, "out")

            code, out, err = run(
                ["batch", *files, "--out-dir", out_dir, "--workers", "2"]
            )

            self.assertEqual(code, 0)
            produced = sorted(os.listdir(out_dir))
            self.assertEqual(
                produced, ["f0.txt.masked", "f1.txt.masked", "f2.txt.masked"]
            )
            for name in produced:
                with open(os.path.join(out_dir, name), encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn(_EMAIL, content)
                self.assertIn("[EMAIL_1]", content)
                # Каждый файл содержит ровно одну находку.
                self.assertIn(name + ": 1", out)


if __name__ == "__main__":
    unittest.main()
