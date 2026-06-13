"""Публичный программный API.

    from datashield import redact, scan
    result = redact("мой email a@b.com")
    print(result.masked_text)   # 'мой email [EMAIL_1]'
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any, List, Optional

from datashield.config import Config
from datashield.detectors.base import Finding
from datashield.detectors.registry import build_active
from datashield.engine import RedactionEngine, RedactionResult, restore
from datashield.strategies import make_strategy

__all__ = ["build_engine", "redact", "scan", "restore"]


def build_engine(
    config: Optional[Config] = None,
    *,
    min_confidence: Optional[float] = None,
    only: Optional[Iterable[str]] = None,
    exclude: Optional[Iterable[str]] = None,
    strategy: Optional[Any] = None,
    reversible: Optional[bool] = None,
) -> RedactionEngine:
    config = config if config is not None else Config()
    if strategy is None:
        strategy = make_strategy(
            config.strategy,
            template=config.placeholder_template,
            key=config.pseudonym_key,
        )
    elif isinstance(strategy, str):
        strategy = make_strategy(
            strategy, template=config.placeholder_template, key=config.pseudonym_key
        )
    return RedactionEngine(
        build_active(config),
        placeholder_template=config.placeholder_template,
        min_confidence=(
            min_confidence if min_confidence is not None else config.min_confidence
        ),
        allowlist=config.allowlist,
        only=only,
        exclude=exclude,
        strategy=strategy,
        reversible=config.reversible if reversible is None else reversible,
    )


def redact(text: str, config: Optional[Config] = None, **kwargs) -> RedactionResult:
    return build_engine(config, **kwargs).redact(text)


def scan(text: str, config: Optional[Config] = None, **kwargs) -> List[Finding]:
    return build_engine(config, **kwargs).analyze(text)
