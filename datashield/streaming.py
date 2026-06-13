"""Потоковая редакция больших файлов с постоянным расходом памяти.

Обрабатывает файл блоками по N строк (внутри блока многострочные находки
работают). Подходит для логов/выгрузок в гигабайты. Ограничение: находка,
пересекающая границу блока, может быть разорвана — для строко-ориентированных
данных это практически не встречается.
"""
from __future__ import annotations

from typing import IO, Optional

from datashield.engine import RedactionEngine

__all__ = ["redact_stream", "redact_file"]


def redact_stream(
    infile: IO[str],
    outfile: IO[str],
    engine: Optional[RedactionEngine] = None,
    *,
    block_lines: int = 2000,
) -> int:
    """Редактирует текстовый поток построчно-блочно. Возвращает число находок."""
    if engine is None:
        from datashield.api import build_engine

        engine = build_engine()
    total = 0
    buffer: list = []
    for line in infile:
        buffer.append(line)
        if len(buffer) >= block_lines:
            result = engine.redact("".join(buffer))
            outfile.write(result.masked_text)
            total += len(result.findings)
            buffer = []
    if buffer:
        result = engine.redact("".join(buffer))
        outfile.write(result.masked_text)
        total += len(result.findings)
    return total


def redact_file(
    in_path: str,
    out_path: str,
    engine: Optional[RedactionEngine] = None,
    *,
    block_lines: int = 2000,
) -> int:
    """Редактирует файл in_path -> out_path потоково. Возвращает число находок."""
    with open(in_path, encoding="utf-8") as src, open(
        out_path, "w", encoding="utf-8"
    ) as dst:
        return redact_stream(src, dst, engine, block_lines=block_lines)
