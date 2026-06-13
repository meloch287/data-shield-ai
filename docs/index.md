# Data Shield AI

A local, offline privacy layer that masks confidential data before text reaches
an external AI. Pure Python stdlib, zero dependencies.

```python
from datashield import redact
redact("INN 7707083893, card 4111 1111 1111 1111").masked_text
# 'INN [INN_1], card [CREDIT_CARD_1]'
```

- **[README](https://github.com/meloch287/data-shield-ai#readme)** — full
  technical reference: pipeline, architecture, detector catalog, metrics.
- **[Cookbook](cookbook.md)** — practical recipes (LLM proxy, MCP, logging,
  CI, structured data, custom detectors).
- **[Comparison](comparison.md)** — vs Presidio / scrubadub / commercial DLP.
- **Architecture decisions:**
  [zero dependencies](adr/0001-zero-dependencies.md) ·
  [confidence & keyword gating](adr/0002-confidence-and-keyword-gating.md) ·
  [one-way default](adr/0003-one-way-redaction-default.md).

## At a glance

- 75 detectors, 68 data types; RU + EU + US + UK + India + China IDs, secrets,
  contact, network, crypto.
- Checksum-validated (Luhn, INN, СНИЛС, IBAN, Verhoeff, mod-11/97).
- Strategies: placeholder · pseudonym · partial · hash · remove; optional
  reversible vault.
- Compliance mapping (GDPR/HIPAA/PCI-DSS/CCPA); severity & categories.
- Integrations: MCP server, HTTP service, logging filter, CI `check`,
  pre-commit, GitHub Action.
- Measured precision/recall/F1 = 1.0 on the labeled eval corpus, gated in CI.
