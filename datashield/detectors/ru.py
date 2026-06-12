"""Российские детекторы: ИНН, СНИЛС, паспорт РФ, телефон РФ.

ИНН/СНИЛС/паспорт — короткие последовательности цифр, неоднозначные без
контекста, поэтому используют KeywordContextDetector: уверенность поднимается,
когда рядом стоит ключевое слово. Карты РФ (МИР/Visa/MC) ловит международный
детектор credit_card по алгоритму Луна — отдельный детектор не нужен.
"""
from __future__ import annotations

from typing import List

from datashield.detectors.base import KeywordContextDetector, RegexDetector
from datashield.validators import validate_inn, validate_snils

__all__ = ["build"]


def _inn_base_confidence(value: str) -> float:
    # 12-значный ИНН имеет две контрольные цифры → случайное совпадение ~1%.
    # 10-значный — одну → ~10%, поэтому без ключевого слова не маскируем.
    digits = "".join(ch for ch in value if ch.isdigit())
    return 0.72 if len(digits) == 12 else 0.55


def build() -> List[object]:
    return [
        KeywordContextDetector(
            "inn",
            "INN",
            r"(?<!\d)(?:\d{12}|\d{10})(?!\d)",
            _inn_base_confidence,
            0.95,
            r"\bИНН\b",
            validator=validate_inn,
        ),
        KeywordContextDetector(
            "snils",
            "SNILS",
            r"(?<!\d)\d{3}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{2}(?!\d)",
            0.8,
            0.95,
            r"СНИЛС",
            validator=validate_snils,
        ),
        # Паспорт РФ (серия 4 + номер 6) — очень общий формат из 10 цифр,
        # поэтому без слова «паспорт» рядом по умолчанию не маскируется.
        KeywordContextDetector(
            "passport_ru",
            "PASSPORT_RU",
            r"(?<!\d)\d{2}\s?\d{2}\s?\d{6}(?!\d)",
            0.4,
            0.9,
            r"паспорт",
        ),
        RegexDetector(
            "phone_ru",
            "PHONE_RU",
            r"(?<!\w)(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)",
            0.85,
        ),
    ]
