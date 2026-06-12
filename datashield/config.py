"""Загрузка и представление конфигурации.

Формат — JSON (`.datashield.json`), а не TOML: json есть в stdlib любой версии
Python, поэтому навык остаётся без зависимостей даже на 3.9/3.10.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["Config", "load_config", "DEFAULT_CONFIG_NAME"]

DEFAULT_CONFIG_NAME = ".datashield.json"


@dataclass(frozen=True)
class Config:
    min_confidence: float = 0.7
    placeholder_template: str = "[{type}_{n}]"
    disabled_detectors: Tuple[str, ...] = ()
    enabled_detectors: Tuple[str, ...] = ()
    allowlist: Tuple[str, ...] = ()
    custom_patterns: Tuple[Dict[str, Any], ...] = ()


def find_default_config(start: Optional[str] = None) -> Optional[str]:
    directory = start or os.getcwd()
    candidate = os.path.join(directory, DEFAULT_CONFIG_NAME)
    return candidate if os.path.isfile(candidate) else None


def load_config(path: Optional[str] = None) -> Config:
    """Читает конфиг из path или из ./.datashield.json. Без файла — дефолты."""
    resolved = path or find_default_config()
    if not resolved:
        return Config()
    with open(resolved, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Конфиг должен быть JSON-объектом")
    return Config(
        min_confidence=float(data.get("min_confidence", 0.7)),
        placeholder_template=str(data.get("placeholder_template", "[{type}_{n}]")),
        disabled_detectors=tuple(data.get("disabled_detectors", ())),
        enabled_detectors=tuple(data.get("enabled_detectors", ())),
        allowlist=tuple(data.get("allowlist", ())),
        custom_patterns=tuple(data.get("custom_patterns", ())),
    )
