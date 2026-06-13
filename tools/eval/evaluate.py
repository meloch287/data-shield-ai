#!/usr/bin/env python3
"""Считает precision/recall/F1 на размеченном корпусе.

Метрика на уровне (пример, тип): для каждого примера сравниваем множество
ожидаемых типов с множеством найденных. TP/FP/FN агрегируются глобально и по
типам. Запуск: python3 tools/eval/evaluate.py [--json]
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datashield import scan  # noqa: E402

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.jsonl")


def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def evaluate(corpus_path: str = CORPUS) -> Dict:
    with open(corpus_path, encoding="utf-8") as fh:
        examples = [json.loads(line) for line in fh if line.strip()]
    tp = fp = fn = 0
    per_type: Dict[str, List[int]] = defaultdict(lambda: [0, 0, 0])
    fp_examples: List[Dict] = []
    for ex in examples:
        expected = set(ex["types"])
        detected = {f.type for f in scan(ex["text"])}
        for t in expected & detected:
            tp += 1
            per_type[t][0] += 1
        extra = detected - expected
        for t in extra:
            fp += 1
            per_type[t][1] += 1
        for t in expected - detected:
            fn += 1
            per_type[t][2] += 1
        if extra:
            fp_examples.append({"text": ex["text"], "false_positives": sorted(extra)})
    p, r, f = _prf(tp, fp, fn)
    return {
        "examples": len(examples),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
        "per_type": {t: dict(zip(("tp", "fp", "fn"), v)) for t, v in sorted(per_type.items())},
        "false_positive_examples": fp_examples,
    }


def main() -> int:
    result = evaluate()
    if "--json" in sys.argv:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print(f"Корпус: {result['examples']} примеров")
    print(f"TP={result['tp']}  FP={result['fp']}  FN={result['fn']}")
    print(
        f"Precision={result['precision']:.3f}  "
        f"Recall={result['recall']:.3f}  F1={result['f1']:.3f}"
    )
    if result["false_positive_examples"]:
        print("\nЛожные срабатывания:")
        for ex in result["false_positive_examples"]:
            print(f"  {ex['false_positives']}: {ex['text'][:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
