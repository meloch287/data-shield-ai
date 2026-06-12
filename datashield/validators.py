"""Алгоритмы проверки контрольных сумм и энтропии.

Чистые функции без побочных эффектов: их легко тестировать изолированно.
Длины и форматы проверяют детекторы — здесь только математика валидации.
"""
from __future__ import annotations

import math
import re
from collections import Counter

__all__ = [
    "luhn_check",
    "validate_inn",
    "validate_snils",
    "validate_iban",
    "shannon_entropy",
]


def luhn_check(number: str) -> bool:
    """Проверка номера по алгоритму Луна (банковские карты, IMEI и т. п.)."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def validate_inn(inn: str) -> bool:
    """Проверка контрольных цифр ИНН (10 знаков — юрлицо, 12 — физлицо)."""
    if not inn.isdigit():
        return False
    if len(inn) == 10:
        coeffs = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        control = sum(int(inn[i]) * coeffs[i] for i in range(9)) % 11 % 10
        return control == int(inn[9])
    if len(inn) == 12:
        coeffs_1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        coeffs_2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        n1 = sum(int(inn[i]) * coeffs_1[i] for i in range(10)) % 11 % 10
        n2 = sum(int(inn[i]) * coeffs_2[i] for i in range(11)) % 11 % 10
        return n1 == int(inn[10]) and n2 == int(inn[11])
    return False


def validate_snils(snils: str) -> bool:
    """Проверка контрольной суммы СНИЛС (11 цифр, последние 2 — контроль)."""
    digits = re.sub(r"\D", "", snils)
    if len(digits) != 11:
        return False
    number = digits[:9]
    control = int(digits[9:11])
    # Для номеров <= 001-001-998 контрольное число не рассчитывается.
    if int(number) <= 1001998:
        return True
    total = sum(int(number[i]) * (9 - i) for i in range(9))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check == 100:
            check = 0
    return check == control


def validate_iban(iban: str) -> bool:
    """Проверка IBAN по mod-97 (ISO 13616)."""
    compact = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    converted = "".join(
        ch if ch.isdigit() else str(ord(ch) - 55) for ch in rearranged
    )
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


def shannon_entropy(value: str) -> float:
    """Энтропия Шеннона в битах на символ — мера «случайности» строки."""
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
