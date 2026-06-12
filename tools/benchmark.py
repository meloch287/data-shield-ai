#!/usr/bin/env python3
"""Бенчмарк скорости Data Shield AI.

Запуск:  python3 tools/benchmark.py
Печатает холодный старт и пропускную способность на репрезентативном тексте.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datashield import build_engine  # noqa: E402

SAMPLE = (
    "Клиент Иван Петров, email ivan.petrov@example.com, тел +7 916 000 11 22, "
    "ИНН 7707083893, СНИЛС 112-233-445 95, карта 4111 1111 1111 1111, "
    "счёт GB82 WEST 1234 5698 7654 32, ул. Ленина 5, индекс 101000. "
    "Договор подписал Сидоров Пётр Иванович. Ключ AKIAIOSFODNN7EXAMPLE. "
)


def _measure(engine, text, repeats):
    t0 = time.perf_counter()
    for _ in range(repeats):
        engine.redact(text)
    return (time.perf_counter() - t0) / repeats


def main() -> int:
    engine = build_engine()
    engine.redact("warmup a@b.com")  # прогрев компиляции регулярок

    print("Data Shield AI — бенчмарк\n")
    for multiplier in (1, 10, 100):
        text = SAMPLE * multiplier
        repeats = max(5, 200 // multiplier)
        dt = _measure(engine, text, repeats)
        size_kb = len(text) / 1000
        mb_s = (len(text) / 1_000_000) / dt if dt else float("inf")
        print(
            f"  {size_kb:8.1f} КБ | {dt * 1000:7.2f} мс/проход | {mb_s:6.2f} MB/с"
        )

    # Холодный старт отдельным процессом измеряется снаружи; здесь — внутри.
    print("\n  Прогрев (компиляция регулярок) делается один раз на процесс.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
