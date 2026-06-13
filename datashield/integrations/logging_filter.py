"""logging.Filter, маскирующий конфиденциальные данные в логах приложения.

    import logging
    from datashield.integrations.logging_filter import RedactingFilter
    logging.getLogger().addFilter(RedactingFilter())

Маскирует итоговое сообщение (с подставленными аргументами), чтобы ПДн/секреты
не утекали в логи. Без зависимостей.
"""
from __future__ import annotations

import logging
from typing import Optional

from datashield.engine import RedactionEngine

__all__ = ["RedactingFilter"]


class RedactingFilter(logging.Filter):
    def __init__(self, engine: Optional[RedactionEngine] = None, name: str = "") -> None:
        super().__init__(name)
        if engine is None:
            from datashield.api import build_engine

            engine = build_engine()
        self.engine = engine

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - кривое сообщение не должно ломать логи
            return True
        masked = self.engine.redact(message).masked_text
        if masked != message:
            record.msg = masked
            record.args = ()
        return True
