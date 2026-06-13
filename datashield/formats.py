"""Детерминированные format-preserving генераторы фейков для псевдонимизации.

Из (key, value) выводим стабильный поток байтов (sha256), чтобы одно и то же
значение всегда давало один и тот же фейк, а разные key — разные фейки.
Формат (разделители, длина) по возможности сохраняется, чтобы downstream-системы
не падали на форме. Карты делаем валидными по Луну; прочие — формо-сохранными.
"""
from __future__ import annotations

import hashlib
from typing import Iterator, List

from datashield.data.names import EN_GIVEN_NAMES, RU_GIVEN_NAMES

__all__ = [
    "byte_stream",
    "map_digits",
    "fake_card",
    "fake_email",
    "fake_phone",
    "fake_person",
    "fake_for_type",
    "fresh_token",
]


def byte_stream(seed: str) -> Iterator[int]:
    """Бесконечный детерминированный поток байтов из seed."""
    counter = 0
    while True:
        block = hashlib.sha256(f"{seed}\x00{counter}".encode("utf-8")).digest()
        yield from block
        counter += 1


def _luhn_check_digit(digits: str) -> str:
    """Контрольная цифра, делающая digits+cd валидным по Луну."""
    total = 0
    for i, ch in enumerate(reversed(digits + "0")):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def map_digits(original: str, seed: str, *, luhn: bool = False) -> str:
    """Заменяет цифры на детерминированные, сохраняя разделители и длину."""
    positions = [i for i, c in enumerate(original) if c.isdigit()]
    if not positions:
        return original
    gen = byte_stream(seed)
    new: List[str] = list(original)
    new_digits = [str(next(gen) % 10) for _ in positions]
    if new_digits[0] == "0":
        new_digits[0] = "1"
    if luhn and len(new_digits) >= 2:
        body = "".join(new_digits[:-1])
        new_digits[-1] = _luhn_check_digit(body)
    for idx, pos in enumerate(positions):
        new[pos] = new_digits[idx]
    return "".join(new)


def fake_card(original: str, seed: str) -> str:
    return map_digits(original, seed, luhn=True)


def fake_email(seed: str) -> str:
    gen = byte_stream(seed)
    local = "user" + "".join(str(next(gen) % 10) for _ in range(6))
    return f"{local}@example.invalid"


def fake_phone(original: str, seed: str) -> str:
    return map_digits(original, seed)


def _pick(items: tuple, seed: str) -> str:
    gen = byte_stream(seed)
    n = (next(gen) << 8) | next(gen)
    return items[n % len(items)].title()


_RU_POOL = tuple(sorted(RU_GIVEN_NAMES))
_EN_POOL = tuple(sorted(EN_GIVEN_NAMES))


def fake_person(original: str, seed: str) -> str:
    """Фейковое имя: латиница → из EN-словаря, иначе из RU; число слов сохраняем."""
    pool = _EN_POOL if original[:1].isascii() and original[:1].isalpha() else _RU_POOL
    words = max(1, len(original.split()))
    gen = byte_stream(seed)
    out = []
    for _ in range(words):
        n = (next(gen) << 8) | next(gen)
        out.append(pool[n % len(pool)].title())
    return " ".join(out)


_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def fresh_token(original: str, seed: str) -> str:
    """Полностью свежий токен той же длины — НЕ сохраняет ни одного символа
    оригинала (для секретов/токенов: иначе буквы утекли бы)."""
    gen = byte_stream(seed)
    return "".join(_ALNUM[next(gen) % len(_ALNUM)] for _ in range(max(1, len(original))))


def fake_for_type(type_name: str, original: str, seed: str) -> str:
    """Подбирает генератор по типу.

    Важно: формо-сохранную замену цифр применяем ТОЛЬКО к чисто числовым
    значениям (карты/телефоны/ID). Если в значении есть буквы (секреты, токены),
    они и есть тайна — отдаём полностью свежий токен, ничего не сохраняя.
    """
    if type_name == "CREDIT_CARD":
        return fake_card(original, seed)
    if type_name == "EMAIL":
        return fake_email(seed)
    if type_name in ("PHONE", "PHONE_RU"):
        return fake_phone(original, seed)
    if type_name == "PERSON":
        return fake_person(original, seed)
    # Чисто числовое (с разделителями) — формо-сохранно меняем цифры.
    if not any(c.isalpha() for c in original):
        return map_digits(original, seed)
    # Есть буквы → секрет/токен: свежий токен, без утечки исходных символов.
    return fresh_token(original, seed)
