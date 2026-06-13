"""Локальный HTTP-сервис редакции на stdlib (без зависимостей).

POST /redact  {"text": "...", "strategy"?, "preset"?, "min_severity"?} -> {masked_text, stats}
POST /scan    {"text": "..."} -> [{type, category, severity, preview}, ...]
GET  /health  -> {"status": "ok"}

Ядро process() — чистая функция (status, payload), его легко тестировать;
HTTP-обработчик лишь разбирает запрос и зовёт process().
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple

from datashield import __version__, build_engine
from datashield.masking import mask_preview
from datashield.taxonomy import category_of, severity_of

__all__ = ["process", "make_handler", "serve", "MAX_BODY_BYTES"]

MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 МБ — защита от раздувания


def _text(body: Dict[str, Any]) -> str:
    value = body.get("text", "")
    if not isinstance(value, str):
        raise ValueError("'text' должен быть строкой")
    return value


def process(path: str, body: Dict[str, Any]) -> Tuple[int, Any]:
    """Маршрутизация и обработка. Возвращает (HTTP-статус, JSON-объект)."""
    if path == "/health":
        return 200, {"status": "ok", "version": __version__}
    if path == "/redact":
        engine = build_engine(
            strategy=body.get("strategy"),
            preset=body.get("preset"),
            min_severity=body.get("min_severity"),
        )
        result = engine.redact(_text(body))
        return 200, {"masked_text": result.masked_text, "stats": result.stats}
    if path == "/scan":
        findings = build_engine().analyze(_text(body))
        return 200, [
            {
                "type": f.type,
                "category": category_of(f.type),
                "severity": severity_of(f.type),
                "preview": mask_preview(f.value),
            }
            for f in findings
        ]
    return 404, {"error": "not found"}


def make_handler():
    class Handler(BaseHTTPRequestHandler):
        timeout = 15  # сокет-таймаут: не виснуть, если тело не приходит

        def log_message(self, *args):  # тише в stdout
            return

        def _send(self, status: int, payload: Any) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self, body: Dict[str, Any]) -> None:
            """Зовёт process() и всегда отвечает корректным JSON, не роняя
            соединение. Сообщения об ошибках СПЕЦИАЛЬНО обобщённые — содержимое
            запроса (в т. ч. чувствительное) никогда не отражается в ответе."""
            try:
                status, payload = process(self.path, body)
            except (ValueError, TypeError, AttributeError):
                # Некорректный ввод: не-строковый text, неизвестная стратегия/
                # пресет/min_severity и т. п. → 400 без эха ввода.
                self._send(400, {"error": "invalid request"})
                return
            except Exception:  # noqa: BLE001 - не ронять соединение на баге
                self._send(500, {"error": "internal error"})
                return
            self._send(status, payload)

        def do_GET(self):
            self._dispatch({})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._send(400, {"error": "invalid Content-Length"})
                return
            if length < 0:
                self._send(400, {"error": "negative Content-Length"})
                return
            if length > MAX_BODY_BYTES:
                self._send(413, {"error": "body too large"})
                return
            try:
                raw = self.rfile.read(length) if length else b"{}"
            except (TimeoutError, OSError):
                self._send(408, {"error": "request timeout"})
                return
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "invalid JSON body"})
                return
            self._dispatch(body)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), make_handler())
    print(f"Data Shield AI HTTP на http://{host}:{port}  (Ctrl+C для выхода)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
