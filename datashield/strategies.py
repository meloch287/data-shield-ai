"""Стратегии замены найденных значений.

Каждая стратегия по Finding и порядковому номеру выдаёт строку-замену. Флаг
`reversible` говорит, можно ли по vault однозначно восстановить оригинал
(плейсхолдеры и псевдонимы уникальны на значение → да; частичная маскировка и
удаление лоссовые → нет).
"""
from __future__ import annotations

import hashlib

from datashield.detectors.base import Finding
from datashield.formats import fake_for_type

__all__ = [
    "PlaceholderStrategy",
    "PseudonymStrategy",
    "PartialStrategy",
    "HashStrategy",
    "RemoveStrategy",
    "partial_mask",
    "make_strategy",
    "STRATEGIES",
]


def partial_mask(value: str, visible: int = 4, mask_char: str = "*") -> str:
    """Маскирует всё, кроме последних `visible` буквенно-цифровых; разделители оставляет."""
    alnum = [i for i, c in enumerate(value) if c.isalnum()]
    keep = set(alnum[-visible:]) if visible > 0 else set()
    return "".join(
        c if (not c.isalnum() or i in keep) else mask_char
        for i, c in enumerate(value)
    )


class PlaceholderStrategy:
    reversible = True

    def __init__(self, template: str = "[{type}_{n}]") -> None:
        self.template = template

    def generate(self, finding: Finding, n: int) -> str:
        return self.template.format(type=finding.type, n=n)


class PseudonymStrategy:
    reversible = True

    def __init__(self, key: str = "") -> None:
        self.key = key

    def generate(self, finding: Finding, n: int) -> str:
        seed = f"{self.key}\x00{finding.type}\x00{finding.value}"
        return fake_for_type(finding.type, finding.value, seed)


class PartialStrategy:
    reversible = False

    def __init__(self, visible: int = 4, mask_char: str = "*") -> None:
        self.visible = visible
        self.mask_char = mask_char

    def generate(self, finding: Finding, n: int) -> str:
        return partial_mask(finding.value, self.visible, self.mask_char)


class HashStrategy:
    reversible = True

    def __init__(self, key: str = "") -> None:
        self.key = key

    def generate(self, finding: Finding, n: int) -> str:
        digest = hashlib.sha256(
            f"{self.key}\x00{finding.value}".encode("utf-8")
        ).hexdigest()[:10]
        return f"[{finding.type}_{digest}]"


class RemoveStrategy:
    reversible = False

    def __init__(self, marker: str = "") -> None:
        self.marker = marker

    def generate(self, finding: Finding, n: int) -> str:
        return self.marker


STRATEGIES = ("placeholder", "pseudonym", "partial", "hash", "remove")


def make_strategy(
    name: str = "placeholder",
    *,
    template: str = "[{type}_{n}]",
    key: str = "",
    visible: int = 4,
    mask_char: str = "*",
    marker: str = "",
):
    """Фабрика стратегии по имени."""
    if name == "placeholder":
        return PlaceholderStrategy(template)
    if name == "pseudonym":
        return PseudonymStrategy(key)
    if name == "partial":
        return PartialStrategy(visible, mask_char)
    if name == "hash":
        return HashStrategy(key)
    if name == "remove":
        return RemoveStrategy(marker)
    raise ValueError(
        f"Неизвестная стратегия: {name}. Доступны: {', '.join(STRATEGIES)}"
    )
