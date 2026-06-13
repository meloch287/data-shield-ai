"""Маскировка структурированных данных (JSON/NDJSON/CSV/XML) без разрушения
структуры.

Два сигнала: (1) значение-строка прогоняется через движок детекции;
(2) значение под «чувствительным» ключом/заголовком/тегом маскируется целиком,
даже если детекторы его не распознали (password, token, ssn, card…).
Только stdlib (json, csv, xml.etree).
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Callable, Optional

from datashield.api import build_engine
from datashield.engine import RedactionEngine

__all__ = [
    "SENSITIVE_KEY_RE",
    "redact_object",
    "redact_json",
    "redact_ndjson",
    "redact_csv",
    "redact_xml",
    "redact_format",
    "FORMATS",
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


def redact_ndjson(
    text: str,
    engine: Optional[RedactionEngine] = None,
    *,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> str:
    """NDJSON / JSON Lines: каждая непустая строка — отдельный JSON-объект.

    Невалидная JSON-строка маскируется как обычный текст — приватный инструмент
    никогда не выдаёт строку в исходном виде. Пустые строки сохраняются.
    """
    eng = _engine(engine)
    out_lines = []
    for line in text.split("\n"):
        if not line.strip():
            out_lines.append(line)
            continue
        try:
            data = json.loads(line)
        except ValueError:
            out_lines.append(eng.redact(line).masked_text)
            continue
        redacted = redact_object(data, eng, sensitive_key_re=sensitive_key_re)
        out_lines.append(json.dumps(redacted, ensure_ascii=False))
    return "\n".join(out_lines)


def redact_xml(
    text: str,
    engine: Optional[RedactionEngine] = None,
    *,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> str:
    """Маскирует XML, сохраняя структуру: текст узлов и значения атрибутов — через
    движок; узлы/атрибуты с чувствительным именем — целиком ``[REDACTED]``.

    DOCTYPE/ENTITY отклоняются (защита от entity-expansion, «billion laughs»).
    Комментарии отбрасываются (безопасно: потенциальные PII не утекают).
    Префиксы пространств имён могут быть нормализованы (особенность ElementTree).
    """
    import xml.etree.ElementTree as ET

    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError(
            "XML с DOCTYPE/ENTITY отклонён ради защиты от entity-expansion"
        )
    eng = _engine(engine)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Некорректный XML: {exc}") from exc

    def local(name: str) -> str:
        return name.rsplit("}", 1)[-1]  # снять "{namespace}" из "{uri}local"

    def walk(el: "ET.Element", depth: int) -> None:
        # Как и redact_object, ограничиваем глубину: иначе очень вложенный
        # (но валидный) XML дал бы RecursionError вместо аккуратного ValueError.
        if depth > _MAX_DEPTH:
            raise ValueError(
                f"XML вложен глубже {_MAX_DEPTH} уровней — отказ во избежание "
                "переполнения стека"
            )
        tag_sensitive = isinstance(el.tag, str) and bool(
            sensitive_key_re.search(local(el.tag))
        )
        if el.text and el.text.strip():
            el.text = _REDACTED if tag_sensitive else eng.redact(el.text).masked_text
        if el.tail and el.tail.strip():
            el.tail = eng.redact(el.tail).masked_text
        for name, value in list(el.attrib.items()):
            if sensitive_key_re.search(local(name)):
                el.attrib[name] = _REDACTED
            else:
                el.attrib[name] = eng.redact(value).masked_text
        for child in el:
            walk(child, depth + 1)

    walk(root, 0)
    body = ET.tostring(root, encoding="unicode")
    stripped = text.lstrip()
    if stripped.startswith("<?xml"):
        decl = text[: text.index("?>") + 2]
        return decl + "\n" + body
    return body


# Диспетчер форматов: имя → функция (одинаковая сигнатура).
FORMATS: dict[str, Callable[..., str]] = {
    "json-data": redact_json,
    "ndjson": redact_ndjson,
    "csv": redact_csv,
    "xml": redact_xml,
}


def redact_format(
    text: str,
    fmt: str,
    engine: Optional[RedactionEngine] = None,
    *,
    sensitive_key_re: re.Pattern = SENSITIVE_KEY_RE,
) -> str:
    """Маскирует структурированный текст по имени формата (см. ``FORMATS``)."""
    try:
        func = FORMATS[fmt]
    except KeyError:
        raise ValueError(
            f"Неизвестный формат {fmt!r}; доступны: {', '.join(sorted(FORMATS))}"
        ) from None
    return func(text, engine, sensitive_key_re=sensitive_key_re)
