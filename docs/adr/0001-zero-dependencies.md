# ADR 0001 — Zero-dependency core

Status: accepted

## Context

The product runs as a guard in front of LLMs, often invoked per request and
embedded in many environments (CLI, CI, agents, servers). Heavy ML dependencies
(spaCy + models) add hundreds of MB and seconds of cold start.

## Decision

The core uses only the Python standard library. Detection is regex + checksum
validators + gazetteers. ML (Presidio, GLiNER) is an **optional plugin**, loaded
lazily and never required.

## Consequences

- Cold start ~15 ms; trivial install (`pip install data-shield-ai`, no models).
- Deterministic, auditable behavior; easy to reason about and test.
- Free-form NER (arbitrary names/addresses) is weaker without the optional ML
  plugin — accepted trade-off, mitigated by patronymic/context/gazetteer
  heuristics.
