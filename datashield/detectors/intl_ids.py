"""Международные идентификаторы: EU / US / UK / India / China.

Детекторы с сильной контрольной суммой и характерной структурой включены по
умолчанию; форматно-общие (только цифры) — контекстно-зависимые (нужно ключевое
слово рядом), чтобы не путать с произвольными числами.
"""
from __future__ import annotations

from typing import List

from datashield.detectors.base import KeywordContextDetector, RegexDetector
from datashield.validators_intl import (
    validate_aadhaar,
    validate_aba,
    validate_china_id,
    validate_codice_fiscale,
    validate_de_taxid,
    validate_dni_es,
    validate_fr_nir,
    validate_nhs,
    validate_nie_es,
    validate_pesel,
)

__all__ = ["build"]

# 15 цифр с возможными пробелами, начинается с 1/2 (пол), допускает 2A/2B (Корсика).
_FR_NIR = r"(?<![\dA-Z])[12][\s]?\d{2}[\s]?\d{2}[\s]?(?:\d{2}|2[AB])[\s]?\d{3}[\s]?\d{3}[\s]?\d{2}(?![\dA-Z])"


def build() -> List[object]:
    return [
        # --- сильная валидация → по умолчанию включены ---
        # Исключаем дефис/hex-соседей, чтобы не ловить группу UUID/hex как Aadhaar.
        RegexDetector(
            "aadhaar", "AADHAAR",
            r"(?<![\dA-Fa-f-])\d{4}\s?\d{4}\s?\d{4}(?![\dA-Fa-f-])", 0.9,
            validator=validate_aadhaar,
        ),
        RegexDetector("pan_in", "PAN_IN", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.85),
        RegexDetector(
            "china_id", "CHINA_ID",
            r"(?<![\dA-Za-z])\d{17}[\dXx](?![\dA-Za-z])", 0.88,
            validator=validate_china_id,
        ),
        RegexDetector(
            "codice_fiscale", "CODICE_FISCALE",
            r"\b[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z]\b", 0.9,
            validator=validate_codice_fiscale,
        ),
        RegexDetector("fr_nir", "FR_NIR", _FR_NIR, 0.88, validator=validate_fr_nir),
        RegexDetector(
            "dni_es", "DNI_ES", r"\b\d{8}[A-Za-z]\b", 0.8, validator=validate_dni_es
        ),
        RegexDetector(
            "nie_es", "NIE_ES",
            r"\b[XYZxyz]\d{7}[A-Za-z]\b", 0.82, validator=validate_nie_es,
        ),
        # --- форматно-общие → контекстно-зависимые ---
        KeywordContextDetector(
            "nhs_uk", "NHS_UK", r"(?<!\d)\d{3}\s?\d{3}\s?\d{4}(?!\d)",
            0.5, 0.92, r"\bNHS\b", validator=validate_nhs,
        ),
        KeywordContextDetector(
            "pesel_pl", "PESEL", r"(?<!\d)\d{11}(?!\d)",
            0.5, 0.92, r"\bPESEL\b", validator=validate_pesel,
        ),
        KeywordContextDetector(
            "de_taxid", "DE_TAX_ID", r"(?<!\d)\d{11}(?!\d)",
            0.45, 0.9, r"steuer|tax[\s\-]?id|idnr", validator=validate_de_taxid,
        ),
        KeywordContextDetector(
            "aba_us", "ABA_ROUTING", r"(?<!\d)\d{9}(?!\d)",
            0.4, 0.9, r"routing|\bABA\b", validator=validate_aba,
        ),
        KeywordContextDetector(
            "us_passport", "US_PASSPORT", r"\b[A-Z0-9]\d{8}\b",
            0.4, 0.9, r"passport",
        ),
        KeywordContextDetector(
            "us_itin", "US_ITIN", r"(?<!\d)9\d{2}-\d{2}-\d{4}(?!\d)",
            0.5, 0.92, r"\bITIN\b",
        ),
        KeywordContextDetector(
            "uk_sort_code", "UK_SORT_CODE", r"(?<!\d)\d{2}-\d{2}-\d{2}(?!\d)",
            0.4, 0.9, r"sort[\s\-]?code",
        ),
        KeywordContextDetector(
            "china_mobile", "CHINA_MOBILE", r"(?<!\d)1[3-9]\d{9}(?!\d)",
            0.5, 0.9, r"手机|电话|mobile|\bphone\b|\btel\b",
        ),
    ]
