"""Сетевые/инфраструктурные данные: учётки в URL, AWS ARN, гео-координаты."""
from __future__ import annotations

from typing import List

from datashield.detectors.base import KeywordContextDetector, RegexDetector

__all__ = ["build"]


def build() -> List[object]:
    return [
        # user:pass в URL — маскируем учётную часть (group 1).
        # Схема ограничена по длине + \b: иначе жадный `*` по длинному ряду букв
        # даёт O(n^2) бэктрекинг (ReDoS).
        RegexDetector(
            "url_credentials", "URL_CREDENTIALS",
            r"\b[a-z][a-z0-9+.\-]{1,15}://([^/\s:@]+:[^/\s:@]+)@", 0.9, group=1,
        ),
        # ARN содержит 12-значный account id.
        RegexDetector(
            "aws_arn", "AWS_ARN",
            r"\barn:aws[a-z\-]*:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s\"']+", 0.85,
        ),
        # Координаты (широта, долгота) с 4+ знаками — по ключевому слову рядом.
        KeywordContextDetector(
            "geo_coord", "GEO_COORD",
            r"[-+]?\d{1,2}\.\d{4,}\s*,\s*[-+]?\d{1,3}\.\d{4,}",
            0.4, 0.85, r"lat|lon|lng|coord|geo|location|координат|широт|долгот",
        ),
    ]
