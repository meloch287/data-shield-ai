"""Контрольные суммы национальных идентификаторов (расширение покрытия мира).

Чистые функции. Алгоритмы: CPF/CNPJ (Бразилия, mod-11), Canada SIN (Луна),
Australia TFN (взвеш. mod-11), Japan My Number, Korea RRN (mod-11),
Mexico CURP (mod-10 по base-37), VIN (ISO 3779, North America).
"""
from __future__ import annotations

import hashlib
import re

from datashield.validators import luhn_check

__all__ = [
    "validate_cpf",
    "validate_cnpj",
    "validate_sin_ca",
    "validate_tfn_au",
    "validate_mynumber_jp",
    "validate_rrn_kr",
    "validate_curp_mx",
    "validate_vin",
    "validate_tron",
]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(text: str) -> bytes:
    num = 0
    for ch in text:
        num = num * 58 + _B58.index(ch)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


def validate_tron(addr: str) -> bool:
    """TRON base58check: версия 0x41, контрольная сумма double-SHA256."""
    if not (addr.startswith("T") and len(addr) == 34):
        return False
    try:
        raw = _b58decode(addr)
    except ValueError:
        return False
    if len(raw) != 25 or raw[0] != 0x41:
        return False
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return checksum == raw[21:25]


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def validate_cpf(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for length in (9, 10):
        total = sum(int(d[i]) * (length + 1 - i) for i in range(length))
        check = (total * 10) % 11
        if check == 10:
            check = 0
        if check != int(d[length]):
            return False
    return True


def validate_cnpj(value: str) -> bool:
    d = _digits(value)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    w1 = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    w2 = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    for weights, pos in ((w1, 12), (w2, 13)):
        total = sum(int(d[i]) * weights[i] for i in range(pos))
        rem = total % 11
        check = 0 if rem < 2 else 11 - rem
        if check != int(d[pos]):
            return False
    return True


def validate_sin_ca(value: str) -> bool:
    d = _digits(value)
    return len(d) == 9 and luhn_check(d)


def validate_tfn_au(value: str) -> bool:
    d = _digits(value)
    if len(d) not in (8, 9):
        return False
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)[: len(d)]
    return sum(int(d[i]) * weights[i] for i in range(len(d))) % 11 == 0


def validate_mynumber_jp(value: str) -> bool:
    d = _digits(value)
    if len(d) != 12:
        return False
    total = sum(int(d[i]) * (i + 2 if i < 6 else i - 4) for i in range(11))
    rem = total % 11
    check = 0 if rem <= 1 else 11 - rem
    return check == int(d[11])


def validate_rrn_kr(value: str) -> bool:
    d = _digits(value)
    if len(d) != 13:
        return False
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    total = sum(int(d[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10
    return check == int(d[12])


_CURP_ALPHABET = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"


def validate_curp_mx(value: str) -> bool:
    s = value.strip().upper()
    if not re.fullmatch(r"[A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d", s):
        return False
    total = sum(_CURP_ALPHABET.index(s[i]) * (18 - i) for i in range(17))
    check = (10 - (total % 10)) % 10
    return check == int(s[17])


_VIN_TRANSLIT = {
    **{str(n): n for n in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def validate_vin(value: str) -> bool:
    s = value.strip().upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", s):
        return False
    try:
        total = sum(_VIN_TRANSLIT[s[i]] * _VIN_WEIGHTS[i] for i in range(17))
    except KeyError:  # pragma: no cover - regex выше гарантирует наличие ключей
        return False
    rem = total % 11
    expected = "X" if rem == 10 else str(rem)
    return s[8] == expected
