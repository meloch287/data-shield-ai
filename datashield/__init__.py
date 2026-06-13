"""Data Shield AI — локальный фильтр приватности между пользователем и ИИ."""
from __future__ import annotations

__version__ = "1.8.0"

from datashield.api import build_engine, redact, restore, scan
from datashield.config import Config, load_config
from datashield.detectors.base import Finding
from datashield.engine import RedactionEngine, RedactionResult
from datashield.normalize import normalize_text
from datashield.structured import redact_csv, redact_json

__all__ = [
    "__version__",
    "build_engine",
    "redact",
    "scan",
    "restore",
    "redact_json",
    "redact_csv",
    "normalize_text",
    "Config",
    "load_config",
    "Finding",
    "RedactionEngine",
    "RedactionResult",
]
