# ADR 0002 — Confidence thresholds and keyword gating

Status: accepted

## Context

Many identifiers are short digit strings (ИНН, SSN-shaped codes, 9/11-digit
numbers) that collide with order numbers, part numbers and versions. Masking
everything that *could* be an ID destroys ordinary text (high false positives).

## Decision

Every finding carries a confidence in `[0,1]`; the engine keeps
`confidence ≥ min_confidence` (default `0.70`). Structurally ambiguous values are
emitted **below** threshold and only boosted when a keyword (`ИНН`, `СНИЛС`,
`SSN`, `БИК`, …) appears within a 25-char window (`KeywordContextDetector`).
Checksums (Luhn, INN, IBAN, Verhoeff, mod-11/97) gate the rest.

## Consequences

- Low false positives on real-world text (measured precision 1.0 on the eval
  corpus); order/part numbers and versions are not masked.
- Some bare IDs are missed without a nearby keyword — tunable via
  `--min-confidence` and documented per detector.
- The eval corpus + `tests/test_eval_metrics.py` gate this trade-off in CI.
