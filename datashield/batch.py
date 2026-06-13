"""Параллельная редакция множества файлов (ProcessPool — обходит GIL на regex).

    from datashield.batch import redact_files
    redact_files([("a.txt", "a.masked"), ("b.log", "b.masked")])
"""
from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Optional, Tuple

__all__ = ["redact_files", "redact_one"]


def redact_one(pair: Tuple[str, str]) -> Tuple[str, int]:
    """Редактирует один файл (потоково). Топ-левел — чтобы был picklable.

    Ошибка по одному файлу изолируется: возвращает count = -1, чтобы один битый
    файл не валил весь батч.
    """
    from datashield.streaming import redact_file

    in_path, out_path = pair
    try:
        count = redact_file(in_path, out_path)
    except OSError:
        return out_path, -1
    return out_path, count


def redact_files(
    pairs: List[Tuple[str, str]],
    *,
    workers: Optional[int] = None,
) -> Dict[str, int]:
    """Редактирует список (in, out) параллельно. Возвращает {out: число находок}."""
    if not pairs:
        return {}
    if workers is None:
        workers = min(len(pairs), (os.cpu_count() or 2))
    if workers <= 1 or len(pairs) == 1:
        return dict(redact_one(p) for p in pairs)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(redact_one, pairs))
