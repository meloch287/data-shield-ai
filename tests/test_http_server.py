"""Тесты HTTP-сервиса редакции (datashield.integrations.http_server).

Проверяем чистую функцию process() и реальный round-trip через
ThreadingHTTPServer на эфемерном порту (port=0), который останавливается
в tearDown. Только stdlib unittest; ассертим фактическое поведение,
наблюдённое в исходниках и при запуске.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from datashield import __version__
from datashield.integrations.http_server import MAX_BODY_BYTES, make_handler, process
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

    def test_post_text_non_string_returns_400_not_dropped(self):
        # Регрессия: process() кидает TypeError/ValueError на не-строковом text.
        # do_POST обязан вернуть чистый 400, а НЕ уронить соединение
        # (RemoteDisconnected). Соединение живо, ответ — корректный JSON.
        for bad in (123, [1, 2], {"nested": 1}, True):
            with self.subTest(text=bad):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    self._post("/redact", {"text": bad})
                self.assertEqual(ctx.exception.code, 400)
                body = json.loads(ctx.exception.read().decode("utf-8"))
                self.assertEqual(body, {"error": "invalid request"})

    def test_post_bad_strategy_returns_400_without_echoing_input(self):
        # Неизвестная стратегия → 400. Сообщение ОБОБЩЁННОЕ: ни имя стратегии,
        # ни (что важнее) значение text не попадают в ответ — гарантия «без
        # утечки» не ослаблена даже в ошибках.
        secret_text = "secret-payload-do-not-echo@hidden.example"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post(
                "/redact",
                {"text": secret_text, "strategy": "definitely-not-a-strategy"},
            )
        self.assertEqual(ctx.exception.code, 400)
        raw_body = ctx.exception.read().decode("utf-8")
        self.assertEqual(json.loads(raw_body), {"error": "invalid request"})
        self.assertNotIn("definitely-not-a-strategy", raw_body)
        self.assertNotIn(secret_text, raw_body)
        self.assertNotIn("hidden.example", raw_body)

    def test_post_bad_preset_returns_400(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post("/redact", {"text": "a@b.com", "preset": "no-such-preset"})
        self.assertEqual(ctx.exception.code, 400)

    def test_unexpected_process_error_returns_500_not_dropped(self):
        # Любая НЕОЖИДАННАЯ ошибка внутри process() (баг) не должна ронять
        # соединение: do_POST/_dispatch ловит её и отвечает 500 без эха.
        from unittest import mock

        def boom(path, body):
            raise RuntimeError("secret-internal-detail-should-not-leak")

        with mock.patch(
            "datashield.integrations.http_server.process", side_effect=boom
        ):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._post("/redact", {"text": "a@b.com"})
        self.assertEqual(ctx.exception.code, 500)
        raw_body = ctx.exception.read().decode("utf-8")
        self.assertEqual(json.loads(raw_body), {"error": "internal error"})
        # Текст исключения не отражается в ответе.
        self.assertNotIn("secret-internal-detail-should-not-leak", raw_body)

    def test_get_unexpected_error_returns_500(self):
        # do_GET тоже обёрнут (симметрия): неожиданная ошибка → 500, не падение.
        from unittest import mock

        with mock.patch(
            "datashield.integrations.http_server.process",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/health")
        self.assertEqual(ctx.exception.code, 500)


class HttpContentLengthTests(unittest.TestCase):
    """DEFECT 3 и семья проверок Content-Length. Сырые сокет-запросы дают полный
    контроль над заголовком Content-Length (urllib его не подделать). Хендлер с
    коротким таймаутом (2с), чтобы тест на «не зависает» был быстрым."""

    def setUp(self):
        base = make_handler()

        class FastHandler(base):  # короткий сокет-таймаут для теста
            timeout = 2

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FastHandler)
        self.host, self.port = self.server.server_address[:2]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _raw_post(self, content_length_header, body=b"", read_timeout=10):
        """Шлёт сырой POST /redact с произвольным Content-Length. Возвращает
        (elapsed_seconds, response_bytes). Читает до конца заголовков или EOF."""
        sock = socket.create_connection((self.host, self.port), timeout=read_timeout)
        sock.settimeout(read_timeout)  # строго больше серверного таймаута
        request = (
            b"POST /redact HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: " + content_length_header + b"\r\n"
            b"\r\n" + body
        )
        start = time.monotonic()
        sock.sendall(request)
        chunks = []
        try:
            while b"\r\n\r\n" not in b"".join(chunks):
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        finally:
            sock.close()
        return time.monotonic() - start, b"".join(chunks)

    def test_content_length_exceeds_body_does_not_hang(self):
        # Заявляем огромный Content-Length, шлём лишь b"{}" и НЕ досылаем остаток.
        # Сервер не виснет бесконечно: сокет-таймаут → 408 в пределах таймаута.
        elapsed, response = self._raw_post(b"999999", body=b"{}")
        self.assertLess(elapsed, 8.0, "сервер завис дольше своего таймаута")
        self.assertIn(b"408", response.split(b"\r\n", 1)[0], response)

    def test_oversized_content_length_rejected_before_read(self):
        # Content-Length больше MAX_BODY_BYTES → 413 СРАЗУ, до чтения тела
        # (поэтому тело не шлём вовсе и зависания быть не может — ответ мгновенный).
        big = str(MAX_BODY_BYTES + 1).encode()
        elapsed, response = self._raw_post(big, body=b"")
        self.assertLess(elapsed, 1.5, "413 должен отдаваться без чтения тела")
        self.assertIn(b"413", response.split(b"\r\n", 1)[0], response)

    def test_invalid_content_length_header_returns_400(self):
        elapsed, response = self._raw_post(b"not-a-number", body=b"")
        self.assertIn(b"400", response.split(b"\r\n", 1)[0], response)

    def test_negative_content_length_returns_400(self):
        elapsed, response = self._raw_post(b"-5", body=b"")
        self.assertIn(b"400", response.split(b"\r\n", 1)[0], response)


if __name__ == "__main__":
    unittest.main()
