<div align="center">

# 🛡️ Data Shield AI

### A privacy layer between you and the AI

Mask confidential data **locally** — before it ever leaves your machine.<br/>
No network. No dependencies. Pure Python.

<br/>

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-701%20passing-success.svg)](#-tests)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![Detectors](https://img.shields.io/badge/detectors-52-orange.svg)](#-features)

<br/>

<b>🌐 Read this in:</b>
<br/>
<a href="README.md"><b>🇬🇧 English</b></a> &nbsp;·&nbsp;
<a href="README.ru.md">🇷🇺 Русский</a> &nbsp;·&nbsp;
<a href="README.zh-CN.md">🇨🇳 中文</a>

</div>

---

```text
in   →   Ivan Petrov, INN 7707083893, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE
out  →   [PERSON_1], INN [INN_1], card [CREDIT_CARD_1], key [AWS_ACCESS_KEY_1]
```

When you send text to an external AI, personal data, financial details, and
secrets easily leak along with the actual task. **Data Shield AI** strips them
out locally, before sending, leaving the AI only the anonymized task.

## 📑 Contents

- [Features](#-features)
- [Install](#-install)
- [Usage](#-usage)
- [Programmatic API](#-programmatic-api)
- [Configuration](#-configuration)
- [Higher-recall modes](#-higher-recall-modes)
- [Speed](#-speed)
- [Privacy](#-privacy)
- [Tests](#-tests)

## ✨ Features

- **Names (PERSON) without ML** — Russian patronymics, context cues ("my name
  is…", "Mr.", "Dear"), and "First Last" pairs from a built-in gazetteer.
  ~15 ms cold start — no slowdown.
- **Russian addresses (ADDRESS)** — streets/avenues/lanes; postal codes.
- **Russia** — INN (10/12 checksum), SNILS, RF passport, RF phone, OGRN/OGRNIP
  (check digit), KPP, BIC, bank account, OMS policy, driver's license.
- **International** — email, phone, bank card (**Luhn-validated**), IBAN
  (mod-97), IPv4/IPv6, MAC, US SSN/EIN, UK NINO, ETH/BTC crypto wallets.
- **Secrets** — AWS / OpenAI / Anthropic / GitHub / GitLab / Google / Slack /
  Stripe / HuggingFace / Shopify and more, JWT, private keys, `password=…`.
- **Stable placeholders** — one value → one placeholder, so the AI can still
  reason about "the same person / the same card" without seeing real data.
- **Low false positives** — checksums instead of naive regexes.
- **Private by default** — originals live in memory only; the report stores only
  salted hashes.
- **Hybrid** — optional ML plugins (Presidio or the lightweight GLiNER) for
  maximum recall on free-form names/addresses/organizations.
- **Zero dependencies.** Python 3.9+. 52 detectors out of the box.

## 📦 Install

```bash
git clone git@github.com:meloch287/data-shield-ai.git
cd data-shield-ai
bash install.sh        # Claude Code skill + the `datashield` command
```

Or use it with no install, straight from the repo:

```bash
python3 -m datashield redact --in input.txt
```

## 🚀 Usage

```bash
# Redact (the main command)
echo "my email a@b.com, INN 7707083893" | datashield redact
# -> my email [EMAIL_1], INN [INN_1]

datashield scan  --in dialog.txt    # show what was found (no masking)
datashield stats --in dialog.txt    # summary by type
datashield detectors                # list all detectors
```

<details>
<summary><b>Useful flags</b></summary>

| Flag | Purpose |
|------|---------|
| `--in / --out` | file instead of stdin/stdout |
| `--only EMAIL,CREDIT_CARD` | only these types |
| `--exclude IP` | exclude these types |
| `--min-confidence 0.5` | confidence threshold (catches more) |
| `--json` | machine-readable output |
| `--report audit.json` | audit without raw values (hashes only) |
| `--config .datashield.json` | custom config |

</details>

## 🐍 Programmatic API

```python
from datashield import redact, scan

result = redact("phone +7 909 123 45 67")
print(result.masked_text)   # 'phone [PHONE_RU_1]'
print(result.stats)          # {'PHONE_RU': 1}

for f in scan("email a@b.com"):
    print(f.type, f.start, f.end, f.confidence)
```

## ⚙️ Configuration

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

## 🎯 Higher-recall modes

**Aggressive names (no dependencies)** — mask single known given names
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

## ⚡ Speed

~15 ms cold start, a typical prompt (1–3 KB) in 1–3 ms. ML plugins load their
model once; the dependency-free core needs no model loading at all.
Benchmark: `python3 tools/benchmark.py`.

## 🔒 Privacy

- Fully local, no network is used.
- Originals are kept in memory only and discarded on exit.
- **One-way redaction** — there is no restoration of originals.
- `--report` contains only the type, position, and a **salted SHA-256 hash**.

## 🧪 Tests

```bash
python3 -m unittest discover -s tests -t .
```

701 tests, stdlib `unittest` only, green on Python 3.9–3.13.

## 📄 License

[MIT](LICENSE) © Саша

<div align="center"><sub>Built for privacy-first AI workflows · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md">中文</a></sub></div>
