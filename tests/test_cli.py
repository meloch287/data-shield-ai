"""Тесты CLI: ввод/вывод, JSON, коды возврата."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main


def run(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    real_stdin = None
    if stdin_text is not None:
        import sys

        real_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        if stdin_text is not None:
            import sys

            sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


class RedactCommandTests(unittest.TestCase):
    def test_redact_stdin(self):
        code, out, _ = run(["redact"], stdin_text="пиши на a@b.com")
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("a@b.com", out)

    def test_redact_file_in_out(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.txt")
            dst = os.path.join(d, "out.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("карта 4111 1111 1111 1111")
            code, _, _ = run(["redact", "--in", src, "--out", dst])
            self.assertEqual(code, 0)
            with open(dst, encoding="utf-8") as f:
                masked = f.read()
            self.assertIn("[CREDIT_CARD_1]", masked)

    def test_redact_json(self):
        code, out, _ = run(["redact", "--json"], stdin_text="a@b.com")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["stats"].get("EMAIL"), 1)

    def test_report_written_without_raw_values(self):
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, "r.json")
            run(["redact", "--report", report], stdin_text="почта secret@x.com")
            with open(report, encoding="utf-8") as f:
                data = f.read()
            self.assertNotIn("secret@x.com", data)
            self.assertIn("value_sha256", data)


class ScanCommandTests(unittest.TestCase):
    def test_scan_json(self):
        code, out, _ = run(["scan", "--json"], stdin_text="a@b.com 192.168.0.1")
        self.assertEqual(code, 0)
        items = json.loads(out)
        kinds = {i["type"] for i in items}
        self.assertIn("EMAIL", kinds)
        self.assertIn("IP", kinds)

    def test_scan_empty(self):
        code, out, _ = run(["scan"], stdin_text="нет данных тут")
        self.assertEqual(code, 0)
        self.assertIn("не найдено", out.lower())

    def test_unknown_only_type(self):
        code, _, err = run(["scan", "--only", "NOPE"], stdin_text="a@b.com")
        self.assertEqual(code, 2)
        self.assertIn("Неизвестные типы", err)


class StatsCommandTests(unittest.TestCase):
    def test_stats(self):
        code, out, _ = run(["stats"], stdin_text="a@b.com и c@d.com")
        self.assertEqual(code, 0)
        self.assertIn("EMAIL", out)
        self.assertIn("ВСЕГО", out)


class DetectorsCommandTests(unittest.TestCase):
    def test_detectors_list(self):
        code, out, _ = run(["detectors"])
        self.assertEqual(code, 0)
        self.assertIn("email", out)
        self.assertIn("high_entropy", out)


if __name__ == "__main__":
    unittest.main()
