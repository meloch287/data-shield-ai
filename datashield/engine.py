"""Оркестратор: запускает детекторы, разбирает пересечения, маскирует.

Движок не знает деталей конкретных детекторов — он работает с Finding. Это
позволяет добавлять детекторы (включая ML-плагин) не трогая логику маскировки.
"""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from datashield.detectors.base import Finding
from datashield.masking import ReplacementContext, mask_preview
from datashield.normalize import normalize_text
from datashield.strategies import PlaceholderStrategy
from datashield.taxonomy import SEVERITY_ORDER, category_of, severity_of

__all__ = ["RedactionEngine", "RedactionResult", "resolve_overlaps", "restore"]


def restore(masked_text: str, vault: Dict[str, str]) -> str:
    """Восстанавливает оригиналы по vault (замена → оригинал).

    Замены подставляются от длинных к коротким, чтобы не задеть вложенные токены.
    Работает для обратимых стратегий (placeholder, pseudonym, hash).
    """
    for replacement in sorted(vault, key=len, reverse=True):
        masked_text = masked_text.replace(replacement, vault[replacement])
    return masked_text


def resolve_overlaps(findings: Sequence[Finding]) -> List[Finding]:
    """Из пересекающихся матчей оставляет лучший: выше уверенность, затем длиннее.

    Жадный отбор по приоритету гарантирует детерминированный результат: при
    конфликте `+7…` (PHONE_RU 0.85) и `+7…` (PHONE 0.8) победит более уверенный.
    """
    if not findings:
        return []
    ordered = sorted(
        findings,
        key=lambda f: (-f.confidence, -(f.end - f.start), f.start, f.type),
    )
    # Битовая карта занятых позиций. Кандидат принимается в порядке приоритета,
    # если его диапазон ещё свободен. bytearray.find/срез работают на C-уровне,
    # поэтому суммарно ~O(n) вместо O(k^2) на больших входах с тысячами находок.
    size = max(f.end for f in findings)
    occupied = bytearray(size)
    chosen: List[Finding] = []
    for candidate in ordered:
        if occupied.find(1, candidate.start, candidate.end) == -1:
            occupied[candidate.start:candidate.end] = b"\x01" * (
                candidate.end - candidate.start
            )
            chosen.append(candidate)
    chosen.sort(key=lambda f: f.start)
    return chosen


@dataclass
class RedactionResult:
    original_length: int
    masked_text: str
    findings: List[Finding]
    stats: Dict[str, int]
    placeholders: Dict[str, str]
    vault: Dict[str, str] = field(default_factory=dict)

    def restore(self, text: Optional[str] = None) -> str:
        """Восстановить оригиналы (по своему vault) в masked_text или в `text`."""
        return restore(self.masked_text if text is None else text, self.vault)

    def report(self, salt: Optional[bytes] = None) -> Dict[str, Any]:
        """Аудит-отчёт без сырых значений: тип, позиция, солёный хеш."""
        salt = salt if salt is not None else os.urandom(16)
        entries = []
        for finding in self.findings:
            digest = hashlib.sha256(salt + finding.value.encode("utf-8")).hexdigest()
            entries.append(
                {
                    "type": finding.type,
                    "start": finding.start,
                    "end": finding.end,
                    "confidence": round(finding.confidence, 3),
                    "detector": finding.detector,
                    "category": category_of(finding.type),
                    "severity": severity_of(finding.type),
                    "value_sha256": digest[:32],
                    "preview": mask_preview(finding.value),
                }
            )
        return {
            "salt": salt.hex(),
            "stats": dict(self.stats),
            "total": len(self.findings),
            "entries": entries,
        }


class RedactionEngine:
    def __init__(
        self,
        detectors: Iterable[Any],
        *,
        placeholder_template: str = "[{type}_{n}]",
        min_confidence: float = 0.7,
        allowlist: Sequence[str] = (),
        only: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
        strategy: Optional[Any] = None,
        reversible: bool = False,
        min_severity: str = "",
        normalize: bool = False,
        fold_homoglyphs: bool = False,
        max_input_size: int = 0,
    ) -> None:
        self.detectors = list(detectors)
        self.placeholder_template = placeholder_template
        self.min_confidence = min_confidence
        self.allowlist = tuple(a.lower() for a in allowlist)
        self.only = {t.upper() for t in only} if only else None
        self.exclude = {t.upper() for t in exclude} if exclude else None
        self.strategy = strategy or PlaceholderStrategy(placeholder_template)
        self.reversible = reversible
        self.min_severity_rank = (
            SEVERITY_ORDER.get(min_severity.lower(), -1) if min_severity else -1
        )
        self.normalize = normalize
        self.fold_homoglyphs = fold_homoglyphs
        self.max_input_size = max_input_size

    def _allowed(self, value: str) -> bool:
        low = value.lower()
        for entry in self.allowlist:
            if low == entry or entry in low:
                return True
        return False

    def _prepare(self, text: str) -> str:
        if self.max_input_size and len(text) > self.max_input_size:
            raise ValueError(
                f"Ввод {len(text)} символов превышает лимит {self.max_input_size}"
            )
        if self.normalize:
            text = normalize_text(text, homoglyphs=self.fold_homoglyphs)
            # NFKC может расширить строку — повторная проверка против DoS.
            if self.max_input_size and len(text) > self.max_input_size:
                raise ValueError(
                    f"После нормализации ввод {len(text)} символов превышает "
                    f"лимит {self.max_input_size}"
                )
        return text

    def analyze(self, text: str) -> List[Finding]:
        return self._analyze(self._prepare(text))

    def _analyze(self, text: str) -> List[Finding]:
        raw: List[Finding] = []
        for detector in self.detectors:
            raw.extend(detector.detect(text))
        filtered: List[Finding] = []
        for finding in raw:
            if finding.confidence < self.min_confidence:
                continue
            if self.only is not None and finding.type not in self.only:
                continue
            if self.exclude is not None and finding.type in self.exclude:
                continue
            if self._allowed(finding.value):
                continue
            if self.min_severity_rank >= 0 and (
                SEVERITY_ORDER.get(severity_of(finding.type), 1)
                < self.min_severity_rank
            ):
                continue
            filtered.append(finding)
        return resolve_overlaps(filtered)

    def redact(self, text: str) -> RedactionResult:
        text = self._prepare(text)
        findings = self._analyze(text)
        context = ReplacementContext(self.strategy)
        parts: List[str] = []
        cursor = 0
        for finding in findings:
            parts.append(text[cursor:finding.start])
            parts.append(context.replacement_for(finding))
            cursor = finding.end
        parts.append(text[cursor:])
        stats = Counter(f.type for f in findings)
        return RedactionResult(
            original_length=len(text),
            masked_text="".join(parts),
            findings=findings,
            stats=dict(stats),
            placeholders=context.mapping,
            vault=context.vault() if self.reversible else {},
        )
