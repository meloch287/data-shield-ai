"""Опциональный ML-детектор имён/адресов через Microsoft Presidio.

Это «гибридная» часть: ядро работает без него, а при установленном Presidio
включается распознавание свободных персональных данных (имена, локации).
Загрузка ленивая — тяжёлые модели не трогаются, пока детектор не вызван.
Если Presidio не установлен, detect() возвращает [] и помечает себя как
недоступный — движок продолжает работать на ядре.
"""
from __future__ import annotations

from typing import List, Optional

from datashield.detectors.base import Finding

__all__ = ["MlDetector", "build_optional"]

# Карта сущностей Presidio → наши типы плейсхолдеров.
_ENTITY_MAP = {
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "NRP": "PERSON",
    "ORGANIZATION": "ORG",
}


class MlDetector:
    name = "ml"
    type = "PERSON"

    def __init__(self, language: str = "en", confidence: float = 0.85) -> None:
        self.language = language
        self.confidence = confidence
        self._analyzer = None
        self._loaded = False
        self.available = True
        self.load_error: Optional[str] = None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore

            self._analyzer = AnalyzerEngine()
            self.available = True
        except Exception as exc:  # noqa: BLE001 - отсутствие пакета не должно падать
            self.available = False
            self.load_error = str(exc)

    def detect(self, text: str) -> List[Finding]:
        self._ensure_loaded()
        if not self.available or self._analyzer is None:
            return []
        findings: List[Finding] = []
        results = self._analyzer.analyze(
            text=text, language=self.language, entities=list(_ENTITY_MAP)
        )
        for res in results:
            mapped = _ENTITY_MAP.get(res.entity_type)
            if not mapped:
                continue
            findings.append(
                Finding(
                    mapped,
                    res.start,
                    res.end,
                    text[res.start:res.end],
                    min(self.confidence, float(res.score)),
                    self.name,
                )
            )
        return findings


def build_optional() -> List[MlDetector]:
    return [MlDetector()]
