"""Регресс на устойчивость серверов (адверсариал-аудит Блока G)."""
import io
import unittest

from datashield.integrations.http_server import MAX_BODY_BYTES, process
from datashield.integrations.mcp_server import handle, serve_stdio


class McpRobustnessTests(unittest.TestCase):
    def test_handle_non_dict_returns_none(self):
        for bad in ([1, 2, 3], 12345, "str", None, 3.14):
            self.assertIsNone(handle(bad))

    def test_serve_stdio_survives_non_object_lines(self):
        out = io.StringIO()
        serve_stdio(
            io.StringIO('[1,2,3]\n12345\n"x"\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n'),
            out,
        )
        # битые строки пропущены, валидный ping обработан
        self.assertIn('"id": 7', out.getvalue())
        self.assertEqual(out.getvalue().strip().count("\n"), 0)  # ровно один ответ


class HttpRobustnessTests(unittest.TestCase):
    def test_non_string_text_raises_valueerror(self):
        for bad in (12345, [1], {"a": 1}, None):
            with self.assertRaises(ValueError):
                process("/redact", {"text": bad})
            with self.assertRaises(ValueError):
                process("/scan", {"text": bad})

    def test_max_body_constant_reasonable(self):
        self.assertGreaterEqual(MAX_BODY_BYTES, 1024 * 1024)

    def test_health_and_redact_still_work(self):
        self.assertEqual(process("/health", {})[0], 200)
        status, payload = process("/redact", {"text": "email a@b.com"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["masked_text"], "email [EMAIL_1]")


if __name__ == "__main__":
    unittest.main()
