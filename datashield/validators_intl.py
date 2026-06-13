"""Контрольные суммы международных идентификаторов.

Чистые функции; длину/формат проверяет детектор, здесь — только математика.
Алгоритмы: Verhoeff (Aadhaar), mod-11 (NHS, China ID), взвешенные суммы
(PESEL, ABA), буквенный контроль (Spain DNI/NIE), Codice Fiscale (Италия),
ISO 7064 MOD 11,10 (Germany Steuer-ID), mod-97 (France NIR).
"""
from __future__ import annotations

import re

__all__ = [
    "verhoeff_check",
    "validate_aadhaar",
    "validate_nhs",
    "validate_pesel",
    "validate_china_id",
    "validate_aba",
    "validate_dni_es",
    "validate_nie_es",
    "validate_codice_fiscale",
    "validate_de_taxid",
    "validate_fr_nir",
]

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_check(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def validate_aadhaar(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or digits[0] in "01":
        return False
    return verhoeff_check(digits)


def validate_nhs(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if len(d) != 10:
        return False
    total = sum(int(d[i]) * (10 - i) for i in range(9))
    check = 11 - total % 11
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == int(d[9])


def validate_pesel(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if len(d) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(d[i]) * weights[i] for i in range(10))
    return (10 - total % 10) % 10 == int(d[10])


def validate_china_id(value: str) -> bool:
    d = value.strip().upper()
    if len(d) != 18 or not d[:17].isdigit():
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    codes = "10X98765432"
    total = sum(int(d[i]) * weights[i] for i in range(17))
    return codes[total % 11] == d[17]


def validate_aba(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if len(d) != 9:
        return False
    total = (
        3 * (int(d[0]) + int(d[3]) + int(d[6]))
        + 7 * (int(d[1]) + int(d[4]) + int(d[7]))
        + (int(d[2]) + int(d[5]) + int(d[8]))
    )
    return total % 10 == 0


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def validate_dni_es(value: str) -> bool:
    m = re.fullmatch(r"(\d{8})([A-Z])", value.strip().upper())
    if not m:
        return False
    return _DNI_LETTERS[int(m.group(1)) % 23] == m.group(2)


def validate_nie_es(value: str) -> bool:
    m = re.fullmatch(r"([XYZ])(\d{7})([A-Z])", value.strip().upper())
    if not m:
        return False
    prefix = {"X": "0", "Y": "1", "Z": "2"}[m.group(1)]
    return _DNI_LETTERS[int(prefix + m.group(2)) % 23] == m.group(3)


_CF_ODD = {
    "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17, "8": 19,
    "9": 21, "A": 1, "B": 0, "C": 5, "D": 7, "E": 9, "F": 13, "G": 15, "H": 17,
    "I": 19, "J": 21, "K": 2, "L": 4, "M": 18, "N": 20, "O": 11, "P": 3, "Q": 6,
    "R": 8, "S": 12, "T": 14, "U": 16, "V": 10, "W": 22, "X": 25, "Y": 24, "Z": 23,
}
_CF_EVEN = {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8,
    "9": 9, "A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7,
    "I": 8, "J": 9, "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15,
    "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23,
    "Y": 24, "Z": 25,
}


def validate_codice_fiscale(value: str) -> bool:
    s = value.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{16}", s):
        return False
    total = 0
    for i, ch in enumerate(s[:15]):
        total += _CF_EVEN[ch] if (i + 1) % 2 == 0 else _CF_ODD[ch]
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[total % 26] == s[15]


def validate_de_taxid(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if len(d) != 11 or d[0] == "0":
        return False
    product = 10
    for i in range(10):
        s = (int(d[i]) + product) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    check = (11 - product) % 10
    return check == int(d[10])


def validate_fr_nir(value: str) -> bool:
    raw = re.sub(r"\s", "", value).upper()
    if len(raw) != 15:
        return False
    body = raw[:13].replace("2A", "19").replace("2B", "18")
    key = raw[13:]
    if not body.isdigit() or not key.isdigit():
        return False
    return 97 - (int(body) % 97) == int(key)
