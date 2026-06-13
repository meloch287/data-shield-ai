"""Международные детекторы: email, телефон, карта, IBAN, IP, MAC."""
from __future__ import annotations

import re
from typing import List

from datashield.detectors.base import RegexDetector
from datashield.validators import luhn_check, validate_iban

__all__ = ["build"]


def _credit_card_validator(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not (13 <= len(digits) <= 19):
        return False
    # Реальные карты не начинаются с 0 и не состоят из одной повторяющейся цифры
    # (00000…, 1111… проходят Луна, но это номера заказов/трекинга, не карты).
    if digits[0] == "0" or len(set(digits)) == 1:
        return False
    return luhn_check(digits)


# IPv6: либо полная форма из 8 групп, либо любая форма со сжатием `::`.
# Требование `::` или 8 групп исключает ложные срабатывания на времени (12:34:56).
# Ветки со сжатием покрывают до 7 групп с любой стороны от `::`.
_H = r"[A-Fa-f0-9]{1,4}"
_IPV6 = (
    r"(?<![:\w])("
    rf"(?:{_H}:){{7}}{_H}"                 # полная: 8 групп
    rf"|(?:{_H}:){{1,7}}:"                 # X:...::
    rf"|(?:{_H}:){{1,6}}:{_H}"             # X:...::Y
    rf"|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}"  # X:...::Y:Z
    rf"|(?:{_H}:){{1,4}}(?::{_H}){{1,3}}"  # X:...::Y:Z:W
    rf"|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}"
    rf"|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}"
    rf"|{_H}:(?::{_H}){{1,6}}"             # X::Y:Z:W:...
    rf"|:(?::{_H}){{1,7}}"                 # ::Y:Z:... и ::
    r")(?![:\w])"
)


def build() -> List[RegexDetector]:
    return [
        # Длины local/domain ограничены по RFC: иначе на точечном входе
        # (a.a.a...) `+` даёт O(n^2) бэктрекинг (ReDoS).
        RegexDetector(
            "email",
            "EMAIL",
            r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b",
            0.98,
        ),
        # Международный телефон требует ведущего «+», иначе слишком много шума.
        RegexDetector(
            "phone_intl",
            "PHONE",
            r"(?<!\w)\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){2,4}(?!\d)",
            0.8,
        ),
        # Лукераунды исключают буквенно-цифровое окружение, чтобы карта не
        # матчилась внутри hex-токенов (напр. ETH-адрес 0x...) или ID.
        # Разделители: пробел, дефис, точка, подчёркивание, слэш.
        RegexDetector(
            "credit_card",
            "CREDIT_CARD",
            r"(?<![0-9A-Za-z])\d(?:[ \-._/]?\d){12,18}(?![0-9A-Za-z])",
            0.9,
            validator=_credit_card_validator,
        ),
        # Допускаем запись IBAN группами через пробел (GB82 WEST 1234 ...).
        RegexDetector(
            "iban",
            "IBAN",
            r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}\b",
            0.95,
            validator=validate_iban,
        ),
        RegexDetector(
            "ipv4",
            "IP",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            0.85,
        ),
        RegexDetector("ipv6", "IP", _IPV6, 0.8, group=1),
        RegexDetector(
            "mac",
            "MAC",
            r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
            0.85,
        ),
        # Cisco-нотация MAC из трёх групп по 4 hex через точку.
        RegexDetector(
            "mac_cisco",
            "MAC",
            r"\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b",
            0.85,
        ),
    ]
