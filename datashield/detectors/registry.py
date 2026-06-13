"""Сборка набора детекторов с учётом конфигурации.

Возвращает и активный список (для работы), и полную карту с флагом включённости
(для команды `datashield detectors`). Опциональные детекторы (high_entropy)
по умолчанию выключены и включаются через config.enabled_detectors.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Tuple

from datashield.config import Config
from datashield.detectors import (
    addresses,
    extra,
    gliner_plugin,
    intl_ids,
    ml_plugin,
    names,
    network,
    regex_intl,
    ru,
    secrets,
    world_ids,
)
from datashield.detectors.base import RegexDetector

__all__ = ["DetectorInfo", "build_active", "build_catalog"]


@dataclass(frozen=True)
class DetectorInfo:
    detector: Any
    default_enabled: bool
    enabled: bool


def _plugin_detectors() -> List[Any]:
    """Детекторы из сторонних пакетов через entry_points группы
    `datashield.detectors`. Каждый entry point — вызываемое, возвращающее список
    детекторов. Сбой одного плагина не ломает остальные."""
    found: List[Any] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover
        return found
    try:
        eps = entry_points()
        group = (
            eps.select(group="datashield.detectors")
            if hasattr(eps, "select")
            else eps.get("datashield.detectors", [])  # type: ignore
        )
    except Exception:  # noqa: BLE001 - discovery не должен падать
        return found
    for ep in group:
        try:
            builder = ep.load()
            for det in builder():
                # Принимаем только то, что похоже на детектор (есть name/type/detect),
                # иначе кривой плагин уронил бы каталог.
                if (
                    hasattr(det, "name")
                    and hasattr(det, "type")
                    and callable(getattr(det, "detect", None))
                ):
                    found.append(det)
        except Exception:  # noqa: BLE001 - один плохой плагин не валит всё
            continue
    return found


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
    pairs += [(d, True) for d in extra.build()]
    pairs += [(d, True) for d in intl_ids.build()]
    pairs += [(d, True) for d in world_ids.build()]
    pairs += [(d, True) for d in network.build()]
    pairs += [(d, True) for d in addresses.build()]
    pairs += [(d, True) for d in names.build()]
    pairs += [(d, False) for d in names.build_optional()]
    pairs += [(d, True) for d in secrets.build()]
    pairs += [(d, False) for d in secrets.build_optional()]
    pairs += [(d, False) for d in ml_plugin.build_optional()]
    pairs += [(d, False) for d in gliner_plugin.build_optional()]
    pairs += [(d, True) for d in _plugin_detectors()]
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
