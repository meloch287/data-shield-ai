"""Маскировка структурированных данных (JSON/CSV) без разрушения структуры.

Два сигнала: (1) значение-строка прогоняется через движок детекции;
(2) значение под «чувствительным» ключом/заголовком маскируется целиком,
даже если детекторы его не распознали (password, token, ssn, card…).
Только stdlib (json, csv).
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Optional

from datashield.api import build_engine
from datashield.engine import RedactionEngine

__all__ = [
    "SENSITIVE_KEY_RE",
    "redact_object",
    "redact_json",
    "redact_csv",
]

# Длинные термины ищем как подстроку (ловит snake_case/camelCase/«с пробелом»:
# user_password, userPassword, "API Key"); короткие неоднозначные — только как
# отдельное слово (\b), чтобы "shipping" не схватило "pin".
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[\s_\-]?key|access[\s_\-]?key|"
    r"private[\s_\-]?key|client[\s_\-]?secret|credential|card[\s_\-]?number|"
    r"credit[\s_\-]?card|social[\s_\-]?security|пароль|секрет|токен)"
    r"|\b(?:ssn|cvv|cvc|pin|otp|pwd)\b"
)
_REDACTED = "[REDACTED]"
_MAX_DEPTH = 200


def _engine(engine: Optional[RedactionEngine]) -> RedactionEngine:
    return engine if engine is not None else build_engine()


def redact_object(
    obj: Any,
    engine: Optional[RedactionEngine] = None,
    *,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> Any:
    """Рекурсивно маскирует JSON-подобный объект, сохраняя структуру."""
    eng = _engine(engine)

    def walk(node: Any, key_is_sensitive: bool, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError(
                f"Структура вложена глубже {_MAX_DEPTH} уровней — отказ во избежание "
                "переполнения стека"
            )
        if key_is_sensitive and not isinstance(node, (dict, list)):
            return _REDACTED
        if isinstance(node, dict):
            return {
                k: walk(
                    v,
                    bool(isinstance(k, str) and sensitive_key_re.search(k)),
                    depth + 1,
                )
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [walk(v, False, depth + 1) for v in node]
        if isinstance(node, str):
            return eng.redact(node).masked_text
        return node

    return walk(obj, False, 0)


def redact_json(
    text: str,
    engine: Optional[RedactionEngine] = None,
    *,
    indent: Optional[int] = 2,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> str:
    """Маскирует JSON-текст, возвращает JSON-текст той же структуры."""
    data = json.loads(text)
    redacted = redact_object(data, engine, sensitive_key_re=sensitive_key_re)
    return json.dumps(redacted, ensure_ascii=False, indent=indent)


def redact_csv(
    text: str,
    engine: Optional[RedactionEngine] = None,
    *,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> str:
    """Маскирует CSV: чувствительные колонки целиком + детекция в каждой ячейке."""
    eng = _engine(engine)
    reader = list(csv.reader(io.StringIO(text)))
    if not reader:
        return text
    header = reader[0]
    sensitive_cols = {
        i for i, name in enumerate(header) if sensitive_key_re.search(name or "")
    }
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    for row in reader[1:]:
        new_row = [
            _REDACTED if i in sensitive_cols else eng.redact(cell).masked_text
            for i, cell in enumerate(row)
        ]
        writer.writerow(new_row)
    return out.getvalue()
