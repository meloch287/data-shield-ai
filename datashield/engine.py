"""Оркестратор: запускает детекторы, разбирает пересечения, маскирует.

Движок не знает деталей конкретных детекторов — он работает с Finding. Это
позволяет добавлять детекторы (включая ML-плагин) не трогая логику маскировки.
"""
from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from datashield.detectors.base import Finding
from datashield.masking import PlaceholderAllocator, mask_preview

__all__ = ["RedactionEngine", "RedactionResult", "resolve_overlaps"]


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
    ) -> None:
        self.detectors = list(detectors)
        self.placeholder_template = placeholder_template
        self.min_confidence = min_confidence
        self.allowlist = tuple(a.lower() for a in allowlist)
        self.only = {t.upper() for t in only} if only else None
        self.exclude = {t.upper() for t in exclude} if exclude else None

    def _allowed(self, value: str) -> bool:
        low = value.lower()
        for entry in self.allowlist:
            if low == entry or entry in low:
                return True
        return False

    def analyze(self, text: str) -> List[Finding]:
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
            filtered.append(finding)
        return resolve_overlaps(filtered)

    def redact(self, text: str) -> RedactionResult:
        findings = self.analyze(text)
        allocator = PlaceholderAllocator(self.placeholder_template)
        parts: List[str] = []
        cursor = 0
        for finding in findings:
            parts.append(text[cursor:finding.start])
            parts.append(allocator.placeholder_for(finding.type, finding.value))
            cursor = finding.end
        parts.append(text[cursor:])
        stats = Counter(f.type for f in findings)
        return RedactionResult(
            original_length=len(text),
            masked_text="".join(parts),
            findings=findings,
            stats=dict(stats),
            placeholders=allocator.mapping,
        )
