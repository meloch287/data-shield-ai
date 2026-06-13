"""Нормализация ввода для устойчивости к обфускации.

- NFKC: полноширинные цифры/совместимые формы (４１１１ → 4111). Безопасно, не
  портит русский/английский текст.
- Гомоглифы (опционально, агрессивно): кириллические двойники латиницы
  сворачиваются ТОЛЬКО в токенах со смешанными алфавитами (pаypal → paypal),
  чтобы не калечить нормальные русские слова (оптимизация остаётся как есть).
"""
from __future__ import annotations

import re
import unicodedata

__all__ = ["nfkc", "fold_homoglyphs", "normalize_text"]

# кириллические (и пара греческих) двойники → латиница
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "і": "i", "ј": "j",
    "ѕ": "s", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y",
    "Х": "X", "К": "K", "М": "M", "Т": "T", "Н": "H", "В": "B", "І": "I",
    "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ι": "i", "ν": "v",
}
_CONFUSABLE_CHARS = set(_CONFUSABLES)
_LATIN_RE = re.compile(r"[A-Za-z]")
_TOKEN_RE = re.compile(r"(\s+)")


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _is_latin(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _fold_token(token: str) -> str:
    # Сворачиваем двойник ТОЛЬКО если хотя бы один сосед — латинская буква
    # (фишинговая сигнатура: одиночная кириллица внутри латинского слова).
    # Так «Москва2024site» не превращается в «Mockba…» — кириллица там окружена
    # кириллицей/цифрами, а не латиницей.
    if not any(ch in _CONFUSABLE_CHARS for ch in token):
        return token
    if not _LATIN_RE.search(token):
        return token
    chars = list(token)
    out = []
    for i, ch in enumerate(chars):
        if ch in _CONFUSABLE_CHARS:
            prev_latin = i > 0 and _is_latin(chars[i - 1])
            next_latin = i + 1 < len(chars) and _is_latin(chars[i + 1])
            if prev_latin or next_latin:
                out.append(_CONFUSABLES[ch])
                continue
        out.append(ch)
    return "".join(out)


def fold_homoglyphs(text: str) -> str:
    """Сворачивает гомоглифы только в смешанных по алфавиту токенах."""
    return "".join(_fold_token(part) for part in _TOKEN_RE.split(text))


def normalize_text(text: str, *, homoglyphs: bool = False) -> str:
    result = nfkc(text)
    if homoglyphs:
        result = fold_homoglyphs(result)
    return result
