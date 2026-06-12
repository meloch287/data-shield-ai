# Security Policy

## Scope

Data Shield AI is a defensive privacy tool. The most security-relevant property
is its **redaction guarantee**: confidential data must not pass through
unmasked, and originals must never be written to disk or sent over the network.

## Reporting a vulnerability

Please report privately to **good177yy@mail.ru** rather than opening a public
issue. Include a minimal reproduction. We aim to respond within 7 days.

High-impact classes we especially want to hear about:

- **Redaction bypass** — input where real PII/secret survives `redact()`.
- **Leak** — any path that writes an original value to disk, logs, or the
  network (the `--report` output must contain only salted hashes).
- **ReDoS / DoS** — input that makes a detector hang or consume excessive memory.

## Non-issues

- Over-masking (a false positive) is a quality bug, not a security issue.
- Missing an exotic data format is a feature request.

## Hardening already in place

- Checksum validation (Luhn, INN, SNILS, IBAN, OGRN) to limit false positives.
- Bounded, non-backtracking-prone regexes; an O(n) overlap resolver.
- A privacy test asserting raw values never appear in any report.
- Adversarial regression suite (`tests/test_adversarial_regression.py`).
