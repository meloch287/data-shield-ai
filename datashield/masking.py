"""Аллокатор плейсхолдеров и помощник предпросмотра.

Гарантирует стабильность: одно и то же значение одного типа в рамках одного
запроса всегда получает один и тот же плейсхолдер. Это позволяет ИИ рассуждать
про «того же человека / ту же карту», не видя реальных данных.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = ["PlaceholderAllocator", "mask_preview"]


class PlaceholderAllocator:
    """Выдаёт типизированные плейсхолдеры с нумерацией по типу."""

    def __init__(self, template: str = "[{type}_{n}]") -> None:
        self.template = template
        self._by_value: Dict[Tuple[str, str], str] = {}
        self._counts: Dict[str, int] = {}

    def placeholder_for(self, type_name: str, value: str) -> str:
        key = (type_name, value)
        existing = self._by_value.get(key)
        if existing is not None:
            return existing
        next_n = self._counts.get(type_name, 0) + 1
        self._counts[type_name] = next_n
        placeholder = self.template.format(type=type_name, n=next_n)
        self._by_value[key] = placeholder
        return placeholder

    @property
    def mapping(self) -> Dict[str, str]:
        """placeholder -> type (без сырых значений, безопасно отдавать наружу)."""
        result: Dict[str, str] = {}
        for (type_name, _value), placeholder in self._by_value.items():
            result[placeholder] = type_name
        return result


def mask_preview(value: str, visible: int = 1) -> str:
    """Безопасный предпросмотр значения для логов: `j****` вместо `john`."""
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible)
