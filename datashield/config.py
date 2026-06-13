"""Загрузка и представление конфигурации.

По умолчанию JSON (`.datashield.json`) — json есть в stdlib любой версии Python.
TOML (`.datashield.toml`) поддерживается на Python 3.11+ через встроенный
tomllib; на 3.9/3.10 TOML недоступен (ясная ошибка). Зависимостей нет.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - зависит от версии Python
    tomllib = None  # type: ignore[assignment]

__all__ = ["Config", "load_config", "DEFAULT_CONFIG_NAME"]

DEFAULT_CONFIG_NAME = ".datashield.json"
DEFAULT_CONFIG_NAMES = (".datashield.json", ".datashield.toml")


@dataclass(frozen=True)
class Config:
    min_confidence: float = 0.7
    placeholder_template: str = "[{type}_{n}]"
    disabled_detectors: Tuple[str, ...] = ()
    enabled_detectors: Tuple[str, ...] = ()
    allowlist: Tuple[str, ...] = ()
    custom_patterns: Tuple[Dict[str, Any], ...] = ()
    strategy: str = "placeholder"
    pseudonym_key: str = ""
    reversible: bool = False
    preset: str = ""
    min_severity: str = ""
    normalize: bool = False
    fold_homoglyphs: bool = False
    max_input_size: int = 0


def find_default_config(start: Optional[str] = None) -> Optional[str]:
    directory = start or os.getcwd()
    for name in DEFAULT_CONFIG_NAMES:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_config(path: Optional[str] = None) -> Config:
    """Читает конфиг из path или из ./.datashield.json. Без файла — дефолты."""
    resolved = path or find_default_config()
    if not resolved:
        return Config()
    if resolved.endswith(".toml"):
        if tomllib is None:
            raise ValueError("TOML-конфиг требует Python 3.11+ (используйте JSON)")
        with open(resolved, "rb") as handle:
            data = tomllib.load(handle)
    else:
        with open(resolved, encoding="utf-8") as handle:
            data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Конфиг должен быть объектом")
    return Config(
        min_confidence=float(data.get("min_confidence", 0.7)),
        placeholder_template=str(data.get("placeholder_template", "[{type}_{n}]")),
        disabled_detectors=tuple(data.get("disabled_detectors", ())),
        enabled_detectors=tuple(data.get("enabled_detectors", ())),
        allowlist=tuple(data.get("allowlist", ())),
        custom_patterns=tuple(data.get("custom_patterns", ())),
        strategy=str(data.get("strategy", "placeholder")),
        pseudonym_key=str(data.get("pseudonym_key", "")),
        reversible=bool(data.get("reversible", False)),
        preset=str(data.get("preset", "")),
        min_severity=str(data.get("min_severity", "")),
        normalize=bool(data.get("normalize", False)),
        fold_homoglyphs=bool(data.get("fold_homoglyphs", False)),
        max_input_size=int(data.get("max_input_size", 0)),
    )
