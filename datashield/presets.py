"""Пресеты — именованные наборы типов под задачу/регламент.

Пресет сводится к множеству разрешённых типов (через категории таксономии и/или
явный список) и опциональному порогу уверенности. Применяется как фильтр `only`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set

from datashield.taxonomy import types_in_categories

__all__ = ["PRESETS", "PresetResolution", "resolve_preset"]


@dataclass(frozen=True)
class PresetResolution:
    only: Optional[Set[str]]
    min_confidence: Optional[float]

PRESETS: Dict[str, Dict] = {
    # Финансовые данные карт + любые секреты.
    "pci-dss": {"categories": ["financial", "secret"]},
    # Здоровье + идентификаторы личности + контакты.
    "hipaa": {"categories": ["health", "person", "government_id", "contact"]},
    # Широкий охват персональных данных (GDPR).
    "gdpr": {
        "categories": [
            "contact", "person", "government_id", "financial", "health", "crypto"
        ]
    },
    # Только секреты/ключи/токены.
    "secrets-only": {"categories": ["secret"]},
    # Российские госреквизиты.
    "ru-gov": {
        "types": [
            "INN", "SNILS", "PASSPORT_RU", "OGRN", "OGRNIP", "KPP", "BIC",
            "BANK_ACCOUNT", "OMS_POLICY", "DRIVER_LICENSE_RU",
        ]
    },
    # Только высокоуверенные находки.
    "minimal": {"min_confidence": 0.9},
}


def resolve_preset(name: str) -> PresetResolution:
    """name → PresetResolution(only, min_confidence)."""
    if name not in PRESETS:
        raise ValueError(
            f"Неизвестный пресет: {name}. Доступны: {', '.join(sorted(PRESETS))}"
        )
    spec = PRESETS[name]
    only: Optional[Set[str]] = None
    cats = spec.get("categories")
    types = spec.get("types")
    if cats or types:
        only = set()
        if cats:
            only |= types_in_categories(cats)
        if types:
            only |= set(types)
    mc = spec.get("min_confidence")
    return PresetResolution(only=only, min_confidence=float(mc) if mc is not None else None)
