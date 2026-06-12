"""Международные детекторы: email, телефон, карта, IBAN, IP, MAC."""
from __future__ import annotations

import re
from typing import List

from datashield.detectors.base import RegexDetector
from datashield.validators import luhn_check, validate_iban

__all__ = ["build"]


def _credit_card_validator(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 13 <= len(digits) <= 19 and luhn_check(digits)


# IPv6: либо полная форма из 8 групп, либо любая форма со сжатием `::`.
# Требование `::` или 8 групп исключает ложные срабатывания на времени (12:34:56).
_IPV6 = (
    r"(?<![:\w])("
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"          # полная
    r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"                       # ...::
    r"|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}"       # ...::x
    r"|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}"
    r"|::(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4}"      # ::x
    r")(?![:\w])"
)


def build() -> List[RegexDetector]:
    return [
        RegexDetector(
            "email",
            "EMAIL",
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            0.98,
        ),
        # Международный телефон требует ведущего «+», иначе слишком много шума.
        RegexDetector(
            "phone_intl",
            "PHONE",
            r"(?<!\w)\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){2,4}(?!\d)",
            0.8,
        ),
        RegexDetector(
            "credit_card",
            "CREDIT_CARD",
            r"(?<!\d)\d(?:[ \-]?\d){12,18}(?!\d)",
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
    ]
