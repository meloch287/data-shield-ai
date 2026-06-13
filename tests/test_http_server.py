"""Тесты HTTP-сервиса редакции (datashield.integrations.http_server).

Проверяем чистую функцию process() и реальный round-trip через
ThreadingHTTPServer на эфемерном порту (port=0), который останавливается
в tearDown. Только stdlib unittest; ассертим фактическое поведение,
наблюдённое в исходниках и при запуске.
"""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from datashield import __version__
from datashield.integrations.http_server import make_handler, process
from datashield.masking import mask_preview


class ProcessHealthTests(unittest.TestCase):
    def test_health_returns_200_and_status_ok(self):
        status, payload = process("/health", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_health_includes_version(self):
        _, payload = process("/health", {})
        self.assertEqual(payload["version"], __version__)


class ProcessRedactTests(unittest.TestCase):
    def test_redact_masks_email_and_returns_stats(self):
        status, payload = process(
            "/redact", {"text": "напиши john.doe@example.com сегодня"}
        )
        self.assertEqual(status, 200)
        # Плейсхолдер вставлен, исходный email отсутствует.
        self.assertIn("[EMAIL_1]", payload["masked_text"])
        self.assertNotIn("john.doe@example.com", payload["masked_text"])
        # stats — счётчик по типам.
        self.assertEqual(payload["stats"], {"EMAIL": 1})

    def test_redact_empty_text_defaults_to_empty(self):
        # body без ключа text -> body.get("text", "") -> ""
        status, payload = process("/redact", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload["masked_text"], "")
        self.assertEqual(payload["stats"], {})

    def test_redact_response_has_only_expected_keys(self):
        _, payload = process("/redact", {"text": "a@b.com"})
        self.assertEqual(set(payload.keys()), {"masked_text", "stats"})

    def test_redact_honors_hash_strategy(self):
        # default-стратегия даёт нумерованный плейсхолдер [EMAIL_1];
        # hash-стратегия даёт детерминированный хеш-суффикс.
        _, default_payload = process("/redact", {"text": "john.doe@example.com"})
        self.assertIn("[EMAIL_1]", default_payload["masked_text"])

        _, hash_payload = process(
            "/redact", {"text": "john.doe@example.com", "strategy": "hash"}
        )
        masked = hash_payload["masked_text"]
        self.assertNotIn("[EMAIL_1]", masked)
        self.assertTrue(masked.startswith("[EMAIL_"))
        self.assertNotIn("john.doe@example.com", masked)
        # Хеш детерминирован: тот же ввод -> тот же вывод.
        _, hash_payload2 = process(
            "/redact", {"text": "john.doe@example.com", "strategy": "hash"}
        )
        self.assertEqual(masked, hash_payload2["masked_text"])

    def test_redact_honors_min_severity(self):
        # EMAIL — medium, CREDIT_CARD — high. min_severity=high должен
        # маскировать только карту, оставив email нетронутым.
        text = "john.doe@example.com card 4111 1111 1111 1111"
        _, payload = process("/redact", {"text": text, "min_severity": "high"})
        self.assertEqual(payload["stats"], {"CREDIT_CARD": 1})
        self.assertIn("[CREDIT_CARD_1]", payload["masked_text"])
        # email ниже порога — остаётся в открытом виде.
        self.assertIn("john.doe@example.com", payload["masked_text"])

    def test_redact_honors_preset(self):
        # secrets-only сужает набор типов до секретов: EMAIL и IP
        # не маскируются, а OPENAI_KEY — маскируется.
        text = "john.doe@example.com 192.168.1.1 sk-1234567890abcdefghij"
        _, payload = process("/redact", {"text": text, "preset": "secrets-only"})
        self.assertNotIn("EMAIL", payload["stats"])
        self.assertNotIn("IP", payload["stats"])
        self.assertIn("OPENAI_KEY", payload["stats"])
        self.assertIn("john.doe@example.com", payload["masked_text"])


class ProcessScanTests(unittest.TestCase):
    def test_scan_returns_list_with_fields(self):
        status, payload = process("/scan", {"text": "john.doe@example.com"})
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 1)
        item = payload[0]
        self.assertEqual(item["type"], "EMAIL")
        self.assertEqual(item["category"], "contact")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("preview", item)

    def test_scan_preview_never_contains_raw_value(self):
        raw = "john.doe@example.com"
        _, payload = process("/scan", {"text": raw})
        preview = payload[0]["preview"]
        # preview = value[:1] + "*"*(len-1): полное значение скрыто.
        self.assertNotEqual(preview, raw)
        self.assertNotIn(raw, preview)
        self.assertEqual(preview, mask_preview(raw))
        # Только первый символ виден, остальное — звёздочки.
        self.assertTrue(preview.startswith(raw[0]))
        self.assertEqual(preview.count("*"), len(raw) - 1)

    def test_scan_empty_text_returns_empty_list(self):
        status, payload = process("/scan", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload, [])

    def test_scan_multiple_findings_carry_category_and_severity(self):
        _, payload = process("/scan", {"text": "john.doe@example.com и 192.168.1.1"})
        by_type = {item["type"]: item for item in payload}
        self.assertIn("EMAIL", by_type)
        self.assertIn("IP", by_type)
        self.assertEqual(by_type["IP"]["category"], "network")
        self.assertEqual(by_type["IP"]["severity"], "low")
        # Сырые значения не утекают ни в один preview.
        for item in payload:
            self.assertNotIn("john.doe@example.com", item["preview"])
            self.assertNotIn("192.168.1.1", item["preview"])


class ProcessRoutingTests(unittest.TestCase):
    def test_unknown_path_returns_404(self):
        status, payload = process("/nope", {})
        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "not found"})

    def test_root_path_is_not_found(self):
        status, _ = process("/", {})
        self.assertEqual(status, 404)


class HttpRoundTripTests(unittest.TestCase):
    """Реальный сервер на эфемерном порту (port=0), останавливается в tearDown."""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler())
        self.host, self.port = self.server.server_address[:2]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _post(self, path, body, raw=None):
        data = raw if raw is not None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base + path,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_get_health(self):
        status, payload = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["version"], __version__)

    def test_post_redact_round_trip(self):
        status, payload = self._post("/redact", {"text": "пиши john.doe@example.com"})
        self.assertEqual(status, 200)
        self.assertIn("[EMAIL_1]", payload["masked_text"])
        self.assertNotIn("john.doe@example.com", payload["masked_text"])
        self.assertEqual(payload["stats"], {"EMAIL": 1})

    def test_post_scan_round_trip(self):
        status, payload = self._post("/scan", {"text": "john.doe@example.com"})
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, list)
        self.assertEqual(payload[0]["type"], "EMAIL")
        self.assertEqual(payload[0]["category"], "contact")
        self.assertNotIn("john.doe@example.com", payload[0]["preview"])

    def test_post_empty_body_uses_defaults(self):
        # Content-Length=0 -> обработчик подставляет b"{}".
        req = urllib.request.Request(
            self.base + "/redact", data=b"", method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 200)
        self.assertEqual(payload["masked_text"], "")

    def test_post_malformed_json_returns_400(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post("/redact", None, raw=b"{not valid json")
        self.assertEqual(ctx.exception.code, 400)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body, {"error": "invalid JSON body"})

    def test_post_non_object_json_returns_400(self):
        # Тело — валидный JSON, но не объект (список) -> 400.
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post("/redact", None, raw=b"[1, 2, 3]")
        self.assertEqual(ctx.exception.code, 400)

    def test_get_unknown_path_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/does-not-exist")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
