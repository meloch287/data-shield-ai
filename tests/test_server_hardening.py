"""Регресс на устойчивость серверов (адверсариал-аудит Блока G)."""
import io
import unittest

from datashield.integrations.http_server import MAX_BODY_BYTES, process
from datashield.integrations.mcp_server import handle, serve_stdio


class McpRobustnessTests(unittest.TestCase):
    def test_handle_non_dict_returns_none(self):
        for bad in ([1, 2, 3], 12345, "str", None, 3.14):
            self.assertIsNone(handle(bad))

    def test_non_object_params_does_not_crash(self):
        # tools/call с params не-объектом не должен ронять handle()
        for bad in (42, "x", [1], None):
            resp = handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": bad}
            )
            self.assertIsNotNone(resp)  # вернул ответ, не упал
        # arguments не-объект тоже
        resp = handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "redact", "arguments": 99},
        })
        self.assertIn("result", resp)

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

    def test_non_string_strategy_raises_handled_error(self):
        # process() с не-строковой strategy поднимает ошибку (do_POST -> 400),
        # а не падает 500.
        with self.assertRaises((ValueError, TypeError, AttributeError)):
            process("/redact", {"text": "a@b.com", "strategy": 123})

    def test_health_and_redact_still_work(self):
        self.assertEqual(process("/health", {})[0], 200)
        status, payload = process("/redact", {"text": "email a@b.com"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["masked_text"], "email [EMAIL_1]")


if __name__ == "__main__":
    unittest.main()
