"""Национальные идентификаторы мира: BR / CA / AU / JP / KR / MX, VIN, крипто.

Сильная валидация и характерная структура → включены по умолчанию; формат-общие
(9–12 цифр) — контекстно-зависимые.
"""
from __future__ import annotations

from typing import List

from datashield.detectors.base import KeywordContextDetector, RegexDetector
from datashield.validators_world import (
    validate_cnpj,
    validate_cpf,
    validate_curp_mx,
    validate_mynumber_jp,
    validate_rrn_kr,
    validate_sin_ca,
    validate_tfn_au,
    validate_tron,
    validate_vin,
)

__all__ = ["build"]


def build() -> List[object]:
    return [
        # --- сильная валидация → по умолчанию ---
        RegexDetector(
            "cpf_br", "CPF_BR",
            r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)", 0.85, validator=validate_cpf,
        ),
        RegexDetector(
            "cnpj_br", "CNPJ_BR",
            r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)", 0.88,
            validator=validate_cnpj,
        ),
        RegexDetector(
            "curp_mx", "CURP_MX",
            r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", 0.9, validator=validate_curp_mx,
        ),
        # TRON: base58check (версия 0x41) → точно, можно по умолчанию.
        RegexDetector(
            "tron_address", "TRON_ADDRESS",
            r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", 0.85, validator=validate_tron,
        ),
        # --- форматно-общие → контекстно-зависимые ---
        # RRN: одиночный mod-11 (~10% случайных проходят) → нужно ключевое слово.
        KeywordContextDetector(
            "rrn_kr", "RRN_KR", r"(?<!\d)\d{6}-?\d{7}(?!\d)",
            0.4, 0.92, r"주민등록번호|resident\s+registration|\bRRN\b",
            validator=validate_rrn_kr,
        ),
        # VIN: контрольная цифра покрывает 1 из 17 позиций (~9% ложных на
        # произвольных 17-символьных токенах) → нужно ключевое слово.
        KeywordContextDetector(
            "vin", "VIN", r"\b[A-HJ-NPR-Z0-9]{17}\b",
            0.4, 0.9, r"\bVIN\b|chassis|vehicle|кузов|шасси|номер\s+кузова",
            validator=validate_vin,
        ),
        # --- форматно-общие → контекстно-зависимые ---
        KeywordContextDetector(
            "sin_ca", "SIN_CA", r"(?<!\d)\d{3}[- ]?\d{3}[- ]?\d{3}(?!\d)",
            0.4, 0.9, r"\bSIN\b|social\s+insurance", validator=validate_sin_ca,
        ),
        KeywordContextDetector(
            "tfn_au", "TFN_AU", r"(?<!\d)\d{3} ?\d{3} ?\d{2,3}(?!\d)",
            0.4, 0.9, r"\bTFN\b|tax\s+file", validator=validate_tfn_au,
        ),
        KeywordContextDetector(
            "mynumber_jp", "MYNUMBER_JP", r"(?<!\d)\d{4} ?\d{4} ?\d{4}(?!\d)",
            0.4, 0.9, r"マイナンバー|個人番号|my\s*number", validator=validate_mynumber_jp,
        ),
        KeywordContextDetector(
            "solana_address", "SOLANA_ADDRESS",
            r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b",
            0.4, 0.85, r"solana|\bSOL\b|phantom",
        ),
    ]
