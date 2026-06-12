"""Опциональный детектор на GLiNER — компактный NER с ONNX-ускорением.

Альтернатива Presidio для тех, кому нужна максимальная полнота по свободным
именам/адресам/организациям, но всё ещё на CPU. Загрузка ленивая; без пакета
`gliner` детектор помечает себя недоступным и возвращает [] — ядро работает.

Включение: в .datashield.json указать "enabled_detectors": ["gliner"].
Установка: pip install gliner onnxruntime
"""
from __future__ import annotations

from typing import List, Optional

from datashield.detectors.base import Finding

__all__ = ["GlinerDetector", "build_optional"]

_LABELS = ["person", "location", "organization", "email", "phone number"]
_LABEL_MAP = {
    "person": "PERSON",
    "location": "LOCATION",
    "organization": "ORG",
    "email": "EMAIL",
    "phone number": "PHONE",
}


class GlinerDetector:
    name = "gliner"
    type = "PERSON"

    def __init__(
        self,
        model: str = "knowledgator/gliner-pii-small-v1.0",
        confidence: float = 0.85,
        threshold: float = 0.5,
    ) -> None:
        self.model_name = model
        self.confidence = confidence
        self.threshold = threshold
        self._model = None
        self._loaded = False
        self.available = True
        self.load_error: Optional[str] = None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            from gliner import GLiNER  # type: ignore

            self._model = GLiNER.from_pretrained(self.model_name)
            self.available = True
        except Exception as exc:  # noqa: BLE001 - отсутствие пакета не должно падать
            self.available = False
            self.load_error = str(exc)

    def detect(self, text: str) -> List[Finding]:
        self._ensure_loaded()
        if not self.available or self._model is None:
            return []
        findings: List[Finding] = []
        entities = self._model.predict_entities(
            text, _LABELS, threshold=self.threshold
        )
        for ent in entities:
            mapped = _LABEL_MAP.get(ent.get("label", ""))
            if not mapped:
                continue
            findings.append(
                Finding(
                    mapped,
                    int(ent["start"]),
                    int(ent["end"]),
                    text[int(ent["start"]):int(ent["end"])],
                    min(self.confidence, float(ent.get("score", self.confidence))),
                    self.name,
                )
            )
        return findings


def build_optional() -> List[GlinerDetector]:
    return [GlinerDetector()]
