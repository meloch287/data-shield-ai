"""Сборка набора детекторов с учётом конфигурации.

Возвращает и активный список (для работы), и полную карту с флагом включённости
(для команды `datashield detectors`). Опциональные детекторы (high_entropy)
по умолчанию выключены и включаются через config.enabled_detectors.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from datashield.config import Config
from datashield.detectors import ml_plugin, regex_intl, ru, secrets
from datashield.detectors.base import RegexDetector

__all__ = ["DetectorInfo", "build_active", "build_catalog"]


@dataclass(frozen=True)
class DetectorInfo:
    detector: Any
    default_enabled: bool
    enabled: bool


def _custom_detectors(config: Config) -> List[RegexDetector]:
    built: List[RegexDetector] = []
    for spec in config.custom_patterns:
        flags = re.IGNORECASE if spec.get("ignore_case") else 0
        built.append(
            RegexDetector(
                str(spec["name"]),
                str(spec.get("type", spec["name"].upper())),
                str(spec["pattern"]),
                float(spec.get("confidence", 0.9)),
                flags=flags,
                group=int(spec.get("group", 0)),
            )
        )
    return built


def build_catalog(config: Config) -> List[DetectorInfo]:
    """Полный каталог детекторов с учётом включения/выключения из конфига."""
    pairs: List[Tuple[Any, bool]] = []
    pairs += [(d, True) for d in regex_intl.build()]
    pairs += [(d, True) for d in ru.build()]
    pairs += [(d, True) for d in secrets.build()]
    pairs += [(d, False) for d in secrets.build_optional()]
    pairs += [(d, False) for d in ml_plugin.build_optional()]
    pairs += [(d, True) for d in _custom_detectors(config)]

    disabled = set(config.disabled_detectors)
    enabled_override = set(config.enabled_detectors)

    catalog: List[DetectorInfo] = []
    for detector, default_on in pairs:
        on = default_on
        if detector.name in disabled or detector.type in disabled:
            on = False
        if detector.name in enabled_override or detector.type in enabled_override:
            on = True
        catalog.append(DetectorInfo(detector, default_on, on))
    return catalog


def build_active(config: Config) -> List[Any]:
    return [info.detector for info in build_catalog(config) if info.enabled]
