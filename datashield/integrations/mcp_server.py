"""Минимальный MCP-сервер (JSON-RPC 2.0 по stdio) — без зависимостей.

Отдаёт инструменты `redact` и `scan`, чтобы любой агент мог локально обезличить
текст перед отправкой во внешнюю модель. Логика в чистой функции handle(),
поэтому её легко тестировать; serve_stdio() — тонкая обёртка цикла ввода/вывода.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from datashield import __version__, build_engine
from datashield.masking import mask_preview
from datashield.taxonomy import category_of, severity_of

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "redact",
        "description": "Маскирует конфиденциальные данные в тексте локально "
        "(ПДн, ключи, карты и т. п.). Возвращает обезличенный текст.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "strategy": {
                    "type": "string",
                    "enum": ["placeholder", "pseudonym", "partial", "hash", "remove"],
                },
                "preset": {"type": "string"},
                "min_severity": {"type": "string"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "scan",
        "description": "Находит конфиденциальные данные без маскировки; "
        "возвращает типы, категории и критичность.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
]


def _result(request_id: Any, result: Dict) -> Dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> Dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _text_content(text: str) -> Dict:
    return {"content": [{"type": "text", "text": text}]}


def _call_tool(name: str, args: Dict) -> Dict:
    text = args.get("text", "")
    if name == "redact":
        engine = build_engine(
            strategy=args.get("strategy"),
            preset=args.get("preset"),
            min_severity=args.get("min_severity"),
        )
        return _text_content(engine.redact(text).masked_text)
    if name == "scan":
        engine = build_engine()
        findings = engine.analyze(text)
        payload = [
            {
                "type": f.type,
                "category": category_of(f.type),
                "severity": severity_of(f.type),
                "preview": mask_preview(f.value),
            }
            for f in findings
        ]
        return _text_content(json.dumps(payload, ensure_ascii=False))
    raise KeyError(name)


def handle(request: Dict) -> Optional[Dict]:
    """Обрабатывает один JSON-RPC запрос. None — если это уведомление."""
    if not isinstance(request, dict):
        return None
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "data-shield-ai", "version": __version__},
        })
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": _TOOLS})
    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        name = str(params.get("name") or "")
        args = params.get("arguments")
        if not isinstance(args, dict):
            args = {}
        try:
            return _result(request_id, _call_tool(name, args))
        except KeyError:
            return _error(request_id, -32602, f"Неизвестный инструмент: {name}")
        except Exception as exc:  # noqa: BLE001 - вернуть ошибку, не падать
            return _result(request_id, {**_text_content(str(exc)), "isError": True})
    if request_id is None:
        return None
    return _error(request_id, -32601, f"Метод не найден: {method}")


def serve_stdio(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(request, dict):
            continue
        response = handle(request)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
