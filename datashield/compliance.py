"""Сопоставление типов данных с регуляторными режимами.

Помогает для DPIA/аудита: какие регламенты затрагивает найденное. Маппинг —
по категориям таксономии; это ориентир, а не юридическая консультация.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from datashield.taxonomy import category_of

__all__ = ["REGULATIONS", "regulations_for", "classify"]

# регламент → покрываемые категории данных
REGULATIONS: Dict[str, set] = {
    "GDPR": {
        "contact", "person", "government_id", "financial", "health",
        "network", "crypto",
    },
    "HIPAA": {"health", "person", "contact", "government_id", "financial", "network"},
    "PCI-DSS": {"financial"},
    "CCPA": {"contact", "person", "government_id", "financial", "network"},
}


def regulations_for(type_name: str) -> List[str]:
    """Регламенты, к которым относится тип (по его категории)."""
    cat = category_of(type_name)
    return sorted(reg for reg, cats in REGULATIONS.items() if cat in cats)


def classify(types: Iterable[str]) -> Dict[str, List[str]]:
    """Из набора найденных типов → {регламент: [затронутые типы]}."""
    result: Dict[str, List[str]] = {}
    for type_name in types:
        for reg in regulations_for(type_name):
            result.setdefault(reg, [])
            if type_name not in result[reg]:
                result[reg].append(type_name)
    return {reg: sorted(v) for reg, v in sorted(result.items())}
