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
from datashield.presets import resolve_preset
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
    preset: Optional[str] = None,
    min_severity: Optional[str] = None,
    normalize: Optional[bool] = None,
    fold_homoglyphs: Optional[bool] = None,
    max_input_size: Optional[int] = None,
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
    # Пресет задаёт набор типов (only) и/или порог уверенности; явные аргументы
    # имеют приоритет над пресетом, пресет — над конфигом.
    preset_name = preset if preset is not None else config.preset
    preset_conf: Optional[float] = None
    if preset_name:
        resolved = resolve_preset(preset_name)
        if only is None and resolved.only is not None:
            only = resolved.only
        preset_conf = resolved.min_confidence
    effective_min_conf = config.min_confidence
    if preset_conf is not None:
        effective_min_conf = preset_conf
    if min_confidence is not None:
        effective_min_conf = min_confidence
    return RedactionEngine(
        build_active(config),
        placeholder_template=config.placeholder_template,
        min_confidence=effective_min_conf,
        allowlist=config.allowlist,
        only=only,
        exclude=exclude,
        strategy=strategy,
        reversible=config.reversible if reversible is None else reversible,
        min_severity=min_severity if min_severity is not None else config.min_severity,
        normalize=config.normalize if normalize is None else normalize,
        fold_homoglyphs=(
            config.fold_homoglyphs if fold_homoglyphs is None else fold_homoglyphs
        ),
        max_input_size=(
            config.max_input_size if max_input_size is None else max_input_size
        ),
    )


def redact(text: str, config: Optional[Config] = None, **kwargs) -> RedactionResult:
    return build_engine(config, **kwargs).redact(text)


def scan(text: str, config: Optional[Config] = None, **kwargs) -> List[Finding]:
    return build_engine(config, **kwargs).analyze(text)
