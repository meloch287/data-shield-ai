<!-- Languages: --> **English** · [Русский](README.ru.md) · [中文](README.zh-CN.md)

# Data Shield AI

**A privacy layer between you and the AI.** A local, offline filter that finds
confidential data in text and replaces it with typed placeholders
(`[EMAIL_1]`, `[INN_1]`, `[CARD_2]`) **before** the text ever leaves your
machine. No network, no dependencies, pure Python stdlib.

```
in:   INN 7707083893, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE
out:  INN [INN_1], card [CREDIT_CARD_1], key [AWS_ACCESS_KEY_1]
```

## Why

When you send text to an external AI, personal data, financial details, and
secrets easily leak along with the actual task. Data Shield AI strips them out
locally, before sending, leaving the AI only the anonymized task.

## Features

- **Names (PERSON) without ML:** Russian patronymics, context cues ("my name
  is…", "Mr.", "Dear"), and "First Last" pairs from a built-in gazetteer.
  ~15 ms cold start — no slowdown.
- **Russian addresses (ADDRESS):** streets/avenues/lanes; postal code by the
  keyword "индекс".
- **Russia:** INN (10/12 checksum), SNILS, RF passport, RF phone, OGRN/OGRNIP
  (check digit), KPP, BIC, bank account, OMS policy, driver's license.
- **International:** email, phone, bank card (**Luhn-validated**), IBAN
  (mod-97), IPv4/IPv6, MAC, US SSN/EIN, UK NINO, ETH/BTC crypto wallets.
- **Secrets:** AWS/OpenAI/Anthropic/GitHub/Google/Slack/Stripe keys, JWT,
  private keys, `password=…`.
- **Stable placeholders:** one value → one placeholder, so the AI can still
  reason about "the same person / the same card" without seeing real data.
- **Low false positives:** checksums instead of naive regexes.
- **Private by default:** originals live in memory only; the report stores only
  salted hashes.
- **Hybrid:** optional ML plugins (Presidio or the lightweight GLiNER) for
  maximum recall on free-form names/addresses/organizations.
- **Zero dependencies.** Python 3.9+. 52 detectors out of the box.

## Install

```bash
git clone git@github.com:meloch287/data-shield-ai.git
cd data-shield-ai
bash install.sh        # Claude Code skill + the `datashield` command
```

Or use it with no install, straight from the repo:

```bash
python3 -m datashield redact --in input.txt
```

## Usage

```bash
# Redact
echo "my email a@b.com, INN 7707083893" | datashield redact
# -> my email [EMAIL_1], INN [INN_1]

# Show what was found (no masking)
datashield scan --in dialog.txt

# Summary by type
datashield stats --in dialog.txt

# List detectors
datashield detectors
```

### Useful flags

| Flag | Purpose |
|------|---------|
| `--in / --out` | file instead of stdin/stdout |
| `--only EMAIL,CREDIT_CARD` | only these types |
| `--exclude IP` | exclude these types |
| `--min-confidence 0.5` | confidence threshold (catches more) |
| `--json` | machine-readable output |
| `--report audit.json` | audit without raw values (hashes only) |
| `--config .datashield.json` | custom config |

## Programmatic API

```python
from datashield import redact, scan

result = redact("phone +7 909 123 45 67")
print(result.masked_text)   # 'phone [PHONE_RU_1]'
print(result.stats)          # {'PHONE_RU': 1}

for f in scan("email a@b.com"):
    print(f.type, f.start, f.end, f.confidence)
```

## Configuration

`.datashield.json` in the working directory (see `.datashield.example.json`):

```json
{
  "min_confidence": 0.7,
  "placeholder_template": "[{type}_{n}]",
  "allowlist": ["example.com"],
  "enabled_detectors": ["high_entropy"],
  "custom_patterns": [
    {"name": "employee_id", "type": "EMPLOYEE_ID", "pattern": "EMP-\\d{6}", "confidence": 0.9}
  ]
}
```

- `allowlist` — values/domains that are never masked.
- `enabled_detectors` — turn on optional ones (`high_entropy`,
  `names_aggressive`, `ml`, `gliner`).
- `disabled_detectors` — turn a detector off by name or type.
- `custom_patterns` — your own regular expressions.

## Higher-recall modes

**Aggressive names (no dependencies):** mask single known given names
(`Ivan`, `John`) at the cost of possible homonyms (`Vera`, `Roman`):
```json
{ "enabled_detectors": ["names_aggressive"] }
```

**ML via GLiNER (lightweight, ONNX on CPU):**
```bash
pip install "data-shield-ai[gliner]"
```
Then `{ "enabled_detectors": ["gliner"] }`.

**ML via Microsoft Presidio (maximum recall):**
```bash
pip install "data-shield-ai[ml]"
python3 -m spacy download en_core_web_lg
```
Then `{ "enabled_detectors": ["ml"] }`. Without the packages installed, the core
keeps working as usual — the plugins simply add no findings.

## Speed

~15 ms cold start, a typical prompt (1–3 KB) in 1–3 ms. ML plugins load their
model once; the dependency-free core needs no model loading at all.
Benchmark: `python3 tools/benchmark.py`.

## Privacy

- Fully local, no network is used.
- Originals are kept in memory only and discarded on exit.
- **One-way redaction** — there is no restoration of originals.
- `--report` contains only the type, position, and a **salted SHA-256 hash**.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## License

MIT — see [LICENSE](LICENSE).
