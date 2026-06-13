# Comparison

How Data Shield AI relates to other PII/secret tools. Pick the right tool for
your constraints.

| | Data Shield AI | Microsoft Presidio | scrubadub | Commercial DLP |
|---|---|---|---|---|
| Runtime dependencies | **0** | spaCy + models (~0.5 GB) | several | SaaS |
| Cold start | ~15 ms | seconds (model load) | ~1 s | network |
| Offline / local | **yes** | yes | yes | usually no |
| Russian gov IDs (ИНН/СНИЛС/…) | **built-in + checksums** | custom recognizers | no | varies |
| Secret/API-key detection | **built-in (25+)** | limited | no | yes |
| Checksum validation | **Luhn/INN/IBAN/Verhoeff/…** | partial | no | yes |
| Reversible round-trip | **optional vault** | anonymizer (separate) | no | varies |
| Compliance mapping | **GDPR/HIPAA/PCI/CCPA** | no | no | yes |
| ML NER | optional plugin (Presidio/GLiNER) | core | no | yes |
| Measured precision/recall | **published, gated in CI** | benchmark-dependent | no | opaque |
| License | MIT | MIT | MIT/GPL | proprietary |

## When to use what

- **Data Shield AI** — when you want an instant, offline, dependency-free guard
  in front of an LLM, with strong structured-ID coverage (incl. Russian and EU)
  and secret detection, and you care about predictable behavior and low false
  positives. Add the Presidio/GLiNER plugin only if you need free-form NER.
- **Presidio** — when free-form person/location/organization NER across many
  languages is the priority and you can afford the model footprint.
- **scrubadub** — lightweight English-centric scrubbing without secrets/IDs.
- **Commercial DLP** — enterprise data-loss prevention across many channels with
  managed policies; heavier and usually cloud-based.

Data Shield AI is designed to be *complementary*: use its fast, deterministic
core for IDs/secrets and optionally delegate free-form names to an ML plugin.
