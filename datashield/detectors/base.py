"""Базовые абстракции детекторов.

Каждый детектор отвечает на один вопрос: «где в тексте данные этого типа?»
и возвращает список Finding. Детекторы не знают про маскировку и пересечения —
это работа движка. Так каждый детектор тестируется изолированно.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Union

__all__ = ["Finding", "RegexDetector", "KeywordContextDetector"]

ConfidenceSpec = Union[float, Callable[[str], float]]


@dataclass(frozen=True)
class Finding:
    """Найденный фрагмент конфиденциальных данных."""

    type: str
    start: int
    end: int
    value: str
    confidence: float
    detector: str

    @property
    def length(self) -> int:
        return self.end - self.start


class RegexDetector:
    """Детектор на регулярном выражении с опциональной валидацией.

    group=0 — маскируется весь матч; group=N — только N-я группа
    (например, в `пароль: hunter2` маскируется только `hunter2`).
    """

    def __init__(
        self,
        name: str,
        type: str,
        pattern: str,
        confidence: float,
        *,
        flags: int = 0,
        group: int = 0,
        validator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.name = name
        self.type = type
        self.regex = re.compile(pattern, flags)
        self.confidence = confidence
        self.group = group
        self.validator = validator

    def detect(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for match in self.regex.finditer(text):
            value = match.group(self.group)
            if value is None:
                continue
            if self.validator is not None and not self.validator(value):
                continue
            start, end = match.span(self.group)
            findings.append(
                Finding(self.type, start, end, value, self.confidence, self.name)
            )
        return findings


class KeywordContextDetector:
    """Детектор, поднимающий уверенность при ключевом слове рядом.

    Нужен для слишком общих идентификаторов (ИНН, СНИЛС, паспорт): сама по себе
    последовательность цифр неоднозначна, но «ИНН 7707083893» — уже почти точно
    персональные данные. base_confidence может быть числом или функцией от
    значения (например, 12-значный ИНН точнее 10-значного).
    """

    def __init__(
        self,
        name: str,
        type: str,
        pattern: str,
        base_confidence: ConfidenceSpec,
        boosted_confidence: float,
        keyword: str,
        *,
        flags: int = 0,
        group: int = 0,
        validator: Optional[Callable[[str], bool]] = None,
        window: int = 25,
    ) -> None:
        self.name = name
        self.type = type
        self.regex = re.compile(pattern, flags)
        self.base_confidence = base_confidence
        self.boosted_confidence = boosted_confidence
        self.keyword = re.compile(keyword, re.IGNORECASE)
        self.group = group
        self.validator = validator
        self.window = window

    def detect(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for match in self.regex.finditer(text):
            value = match.group(self.group)
            if value is None:
                continue
            if self.validator is not None and not self.validator(value):
                continue
            start, end = match.span(self.group)
            context = text[max(0, start - self.window):start]
            if callable(self.base_confidence):
                base = self.base_confidence(value)
            else:
                base = self.base_confidence
            confidence = (
                self.boosted_confidence if self.keyword.search(context) else base
            )
            findings.append(
                Finding(self.type, start, end, value, confidence, self.name)
            )
        return findings
