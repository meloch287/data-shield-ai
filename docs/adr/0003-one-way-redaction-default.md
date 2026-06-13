# ADR 0003 — One-way redaction by default

Status: accepted

## Context

Restoring originals after the model replies is useful, but storing a
placeholder→original vault is itself a place sensitive data can leak.

## Decision

The default is **one-way** redaction: originals live in memory only and are
discarded on exit; nothing is written to disk. Reversibility is **opt-in**
(`reversible=True` / `--vault`), and even then the audit report (`--report`)
stores only types, positions and **salted SHA-256 hashes** — never raw values.

## Consequences

- The safe path is the default; reversibility is a deliberate choice the caller
  makes and must protect (the vault holds originals — keep it local).
- Strategies that are inherently lossy (`partial`, `remove`) are marked
  non-reversible.
