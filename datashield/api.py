"""Публичный программный API.

    from datashield import redact, scan
    result = redact("мой email a@b.com")
    print(result.masked_text)   # 'мой email [EMAIL_1]'
"""
from __future__ import annotations

from typing import Iterable, Optional

from datashield.config import Config, load_config
from datashield.detectors.registry import build_active
from datashield.engine import RedactionEngine, RedactionResult
from datashield.detectors.base import Finding
from typing import List

__all__ = ["build_engine", "redact", "scan"]


def build_engine(
    config: Optional[Config] = None,
    *,
    min_confidence: Optional[float] = None,
    only: Optional[Iterable[str]] = None,
    exclude: Optional[Iterable[str]] = None,
) -> RedactionEngine:
    config = config if config is not None else Config()
    return RedactionEngine(
        build_active(config),
        placeholder_template=config.placeholder_template,
        min_confidence=(
            min_confidence if min_confidence is not None else config.min_confidence
        ),
        allowlist=config.allowlist,
        only=only,
        exclude=exclude,
    )


def redact(text: str, config: Optional[Config] = None, **kwargs) -> RedactionResult:
    return build_engine(config, **kwargs).redact(text)


def scan(text: str, config: Optional[Config] = None, **kwargs) -> List[Finding]:
    return build_engine(config, **kwargs).analyze(text)
