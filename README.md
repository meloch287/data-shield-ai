<div align="center">

# 🛡️ Data Shield AI

Local PII/secret redaction layer. Masks confidential data before text leaves the machine.

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-701%20passing-success.svg)](#tests)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#footprint)
[![Detectors](https://img.shields.io/badge/detectors-75-orange.svg)](#detector-catalog)

<a href="README.md"><b>🇬🇧 English</b></a> &nbsp;·&nbsp;
<a href="README.ru.md">🇷🇺 Русский</a> &nbsp;·&nbsp;
<a href="README.zh-CN.md">🇨🇳 中文</a>

</div>

```text
in   →   Ivan Petrov, INN 7707083893, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE
out  →   [PERSON_1], INN [INN_1], card [CREDIT_CARD_1], key [AWS_ACCESS_KEY_1]
```

Pure Python stdlib, no dependencies, no network. 75 detectors, 68 data types. Same value → same placeholder; originals never written to disk.

- [Pipeline](#pipeline)
- [Architecture](#architecture)
- [Detector catalog](#detector-catalog)
- [Confidence model](#confidence-model)
- [Overlap resolution](#overlap-resolution)
- [Validation algorithms](#validation-algorithms)
- [Strategies & reversibility](#strategies--reversibility)
- [Metrics](#metrics)
- [Privacy model](#privacy-model)
- [Install / Usage / API](#install)
- [Tests](#tests)

## Pipeline

```mermaid
flowchart LR
  subgraph DET["75 detectors run independently"]
    direction TB
    RX["regex + checksum validators"]
    KW["keyword-context base/boost"]
    NM["names gazetteer + heuristics"]
  end
  IN["input text"] --> DET
  DET -->|findings| FIL
  FIL["filter: confidence ≥ min,<br/>allowlist, only/exclude"] --> RES
  RES["resolve overlaps<br/>bytearray occupancy, O of n"] --> ALLOC
  ALLOC["allocate placeholders<br/>value to TYPE_n"] --> OUT["masked text + stats + report"]
```

Each detector emits `Finding(type, start, end, value, confidence, detector)`. The engine never looks inside a detector — it only sees `Finding`, so adding a detector (including the ML plugins) needs no engine change.

## Architecture

```mermaid
flowchart TD
  cli["cli.py<br/>redact · scan · stats · detectors"] --> api["api.py<br/>build_engine / redact / scan"]
  cfg["config.py<br/>.datashield.json"] --> api
  api --> reg["detectors/registry.py<br/>enable/disable, custom patterns"]
  api --> eng["engine.py<br/>RedactionEngine"]
  reg --> det["detectors/*"]
  det --> base["detectors/base.py<br/>RegexDetector · KeywordContextDetector"]
  det --> val["validators.py<br/>Luhn · INN · SNILS · IBAN · OGRN"]
  det --> data["data/names.py<br/>RU/EN gazetteer"]
  eng --> mask["masking.py<br/>PlaceholderAllocator"]
```

| Module | Responsibility | LOC* |
|--------|----------------|-----:|
| `engine.py` | orchestration, overlap resolution, report | ~140 |
| `detectors/base.py` | `Finding`, regex + keyword-context detectors | ~140 |
| `detectors/{regex_intl,ru,extra,secrets,addresses,names}.py` | the 75 detectors | ~600 |
| `detectors/{ml,gliner}_plugin.py` | optional lazy ML adapters | ~200 |
| `validators.py` | Luhn / INN / SNILS / IBAN / OGRN checks | ~110 |
| `masking.py` | stable typed placeholder allocation | ~60 |
| `config.py` · `api.py` · `cli.py` | config, public API, CLI | ~340 |

<sub>* core total: <b>1665</b> lines across 21 files; tests: <b>4725</b> lines across 18 files.</sub>

## Detector catalog

75 detectors → 68 placeholder types. `conf` = confidence; `a→b` = base→boosted when a keyword is in context (25-char window). Below the default threshold `0.70` a finding is dropped, so context-gated IDs do not fire on bare numbers.

**International**

| detector | type | conf | validation |
|----------|------|:----:|------------|
| `email` | EMAIL | 0.98 | — |
| `phone_intl` | PHONE | 0.80 | leading `+` required |
| `credit_card` | CREDIT_CARD | 0.90 | Luhn + reject 0-lead/repeated |
| `iban` | IBAN | 0.95 | mod-97 |
| `ipv4` / `ipv6` | IP | 0.85 / 0.80 | octet range / `::` form |
| `mac` / `mac_cisco` | MAC | 0.85 | — |

**Russia**

| detector | type | conf | validation |
|----------|------|:----:|------------|
| `inn` | INN | var→0.95 | control digit (10/12) |
| `snils` | SNILS | 0.80→0.95 | checksum |
| `passport_ru` | PASSPORT_RU | 0.40→0.90 | context |
| `phone_ru` | PHONE_RU | 0.85 | — |
| `ogrn` / `ogrnip` | OGRN/OGRNIP | 0.85 | control digit |
| `kpp` `bic` `bank_account` `oms_policy` `driver_license_ru` | … | 0.40–0.55→0.90+ | context |
| `address_ru` | ADDRESS | 0.78 | street keyword + capitalized name |
| `postal_code_ru` | POSTAL_CODE | 0.30→0.85 | context (`индекс`) |

**Identity / crypto**

| detector | type | conf | validation |
|----------|------|:----:|------------|
| `us_ssn` `uk_nino` | US_SSN / UK_NINO | 0.50→0.92 | context-gated |
| `us_ein` | US_EIN | 0.40→0.90 | context |
| `eth_address` | ETH_ADDRESS | 0.95 | `0x` + 40 hex |
| `btc_address` | BTC_ADDRESS | 0.78 | base58 / bech32 |
| `names` | PERSON | heuristic | patronymic · context · gazetteer pair |

**International IDs** (checksum-validated unless noted)

| detector | type | conf | validation |
|----------|------|:----:|------------|
| `aadhaar` (India) | AADHAAR | 0.90 | Verhoeff |
| `pan_in` (India) | PAN_IN | 0.85 | shape `AAAAA9999A` |
| `china_id` | CHINA_ID | 0.88 | mod-11 |
| `codice_fiscale` (IT) | CODICE_FISCALE | 0.90 | check char |
| `fr_nir` (France) | FR_NIR | 0.88 | mod-97 |
| `dni_es` / `nie_es` (ES) | DNI_ES / NIE_ES | 0.80 | control letter |
| `nhs_uk` | NHS_UK | 0.50→0.92 | mod-11, context |
| `pesel_pl` `de_taxid` `aba_us` `us_passport` `us_itin` `uk_sort_code` `china_mobile` | … | 0.40–0.50→0.90+ | context-gated |

**Network / infra**

`url_credentials` (masks `user:pass` in `scheme://…@`) · `aws_arn` · `geo_coord` (context-gated).

**Secrets** (0.85–0.99, distinctive prefixes)

`aws_access_key` `aws_secret` `anthropic_key` `openai_key` `github_token` `github_pat` `gitlab_token` `huggingface_token` `npm_token` `google_oauth_secret` `digitalocean_token` `shopify_token` `square_token` `google_api_key` `slack_token` `stripe_key` `sendgrid_key` `twilio_sid` `mailgun_key` `telegram_bot` `discord_token` `ssh_pubkey` `jwt` `private_key` `password` `secret_assignment`

**Optional** (off by default): `high_entropy` (0.75), `names_aggressive` (single given names), `ml` (Presidio), `gliner` (ONNX NER).

## Confidence model

Every finding carries a confidence in `[0,1]`. The engine keeps `confidence ≥ min_confidence` (default `0.70`).

```mermaid
flowchart LR
  A["email 0.98<br/>private key 0.99<br/>API keys 0.95-0.97"] --> M{"≥ 0.70?"}
  B["card 0.90 · IBAN 0.95<br/>RU phone 0.85 · INN-12 0.72"] --> M
  C["passport 0.40 · SSN 0.50<br/>KPP/BIC 0.40-0.55<br/>bare INN-10 0.55"] --> M
  M -->|yes| K["masked"]
  M -->|"no (needs keyword nearby)"| S["kept"]
  C -. "+keyword in 25-char window" .-> P["boost to 0.90+"]
  P --> M
```

Design rule: a value that is structurally ambiguous (a 9–12 digit number, a `NNN-NN-NNNN` code) stays **below** threshold until a keyword (`ИНН`, `СНИЛС`, `SSN`, `БИК`…) appears next to it. This is why order numbers and part numbers are not masked while real, labeled IDs are.

## Overlap resolution

Detectors run independently and produce overlapping candidates (e.g. `+7…` matches both `phone_ru` and `phone_intl`; a digit run inside an ETH address matches `credit_card`). Resolution is greedy by priority:

```mermaid
flowchart TD
  S["sort candidates by<br/>(confidence ↓, length ↓, start ↑)"] --> L["bytearray occupied[max_end]"]
  L --> I{"next candidate"}
  I --> Q{"occupied.find(1, start, end) == -1 ?"}
  Q -->|free| ACC["mark span occupied · accept"]
  Q -->|overlap| SKIP["skip"]
  ACC --> I
  SKIP --> I
```

`occupied.find` / slice-assign run at C level, so the pass is ~O(n) in text length instead of the O(k²) of pairwise interval checks. Result on a 2 MB input with 160 000 distinct findings: **7.2 s → 1.64 s**.

## Validation algorithms

Checksums replace naive regex matching to suppress false positives.

| algorithm | applies to | check |
|-----------|------------|-------|
| Luhn | credit cards | `Σ digits (every 2nd doubled) mod 10 == 0`, reject leading-0 / all-equal |
| INN-10 | legal-entity tax id | weighted sum `mod 11 mod 10 == d[9]` |
| INN-12 | individual tax id | two control digits |
| SNILS | pension id | `Σ d[i]·(9-i) mod 101` → control |
| IBAN | bank account | move 4 chars to tail, letters→numbers, `mod 97 == 1` |
| OGRN/OGRNIP | company reg. | `int(first n) mod (11/13) mod 10 == last` |

## Strategies & reversibility

`redact()` replaces each finding via a **strategy**. With `reversible=True` it also
records a vault (`replacement → original`) so the AI's answer can be un-masked.

| strategy | example output | reversible |
|----------|----------------|:----------:|
| `placeholder` (default) | `[CARD_1]` | yes |
| `pseudonym` | `4574 9172 3643 9348` (Luhn-valid fake, format kept) | yes |
| `partial` | `**** **** **** 1111` | no |
| `hash` | `[CARD_3f9a1c2b80]` | yes |
| `remove` | `` (deleted) | no |

```python
r = redact("card 4111 1111 1111 1111", strategy="pseudonym", reversible=True)
r.masked_text   # 'card 4574 9172 3643 9348'  — fake, passes Luhn
r.restore()     # 'card 4111 1111 1111 1111'  — exact inverse
```

CLI: `datashield redact --strategy pseudonym --vault v.json`, then
`… | datashield restore --vault v.json`. The vault holds originals — keep it local.

## Metrics

Single core, Python 3.14, warm process. Throughput is linear in input size and constant at **~1.05 MB/s**; cold start (import → first redact) is **~15 ms** (vs seconds to load an ML model).

```mermaid
xychart-beta
  title "Latency vs input size (lower is better)"
  x-axis ["1KB", "4KB", "16KB", "64KB", "256KB", "1MB"]
  y-axis "ms per call" 0 --> 1000
  bar [1.05, 3.9, 15.4, 61, 243, 955]
```

| input | ms/call | MB/s |
|------:|--------:|-----:|
| 1 KB | 1.05 | 1.02 |
| 4 KB | 3.90 | 1.03 |
| 16 KB | 15.4 | 1.04 |
| 64 KB | 61.0 | 1.05 |
| 256 KB | 243 | 1.05 |
| 1 MB | 955 | 1.05 |

```mermaid
xychart-beta
  title "Overlap resolution, 2MB / 160k findings (seconds)"
  x-axis ["before: O(k^2)", "after: O(n)"]
  y-axis "seconds" 0 --> 8
  bar [7.2, 1.64]
```

| metric | value |
|--------|-------|
| Detectors / types | 75 / 68 |
| Default-on detectors | 48 |
| Cold start | ~15 ms |
| Throughput | ~1.05 MB/s |
| Tests | **701** (stdlib unittest), green on Python 3.9–3.13 |
| Test runtime | ~6.1 s |
| <a name="footprint"></a>Runtime dependencies | **0** |
| Core size | 1665 LOC / 21 files |

Detectors were hardened by a parallel adversarial audit (13 agents): 13 precision/recall/DoS issues were found and fixed, each locked by a regression test (`tests/test_adversarial_regression.py`).

## Privacy model

```mermaid
flowchart LR
  V["original value"] -->|in memory only| PH["placeholder [TYPE_n]"]
  V -. "--report only" .-> H["salted SHA-256<br/>(truncated)"]
  V -.->|never persisted| X["disk ✗ / network ✗"]
```

- One-way redaction — no restoration path, no vault.
- `--report` writes `{type, start, end, confidence, detector, value_sha256, preview}` — never the raw value.
- A privacy test asserts originals never appear in any report.

## Install

```bash
git clone git@github.com:meloch287/data-shield-ai.git && cd data-shield-ai
bash install.sh        # Claude Code skill + `datashield` command
# or, no install:
python3 -m datashield redact --in input.txt
```

### Usage

```bash
echo "my email a@b.com, INN 7707083893" | datashield redact   # -> [EMAIL_1], INN [INN_1]
datashield scan  --in f.txt        # findings, no masking
datashield stats --in f.txt        # counts by type
datashield detectors               # list all 52
```

Flags: `--in/--out` · `--only T1,T2` · `--exclude T` · `--min-confidence X` · `--json` · `--report audit.json` · `--config path`.

### API

```python
from datashield import redact, scan
redact("phone +7 909 123 45 67").masked_text   # 'phone [PHONE_RU_1]'
[(f.type, f.confidence) for f in scan("a@b.com")]
```

### Config (`.datashield.json`)

```json
{ "min_confidence": 0.7, "allowlist": ["example.com"],
  "enabled_detectors": ["names_aggressive", "gliner"],
  "custom_patterns": [{"name":"employee_id","type":"EMPLOYEE_ID","pattern":"EMP-\\d{6}","confidence":0.9}] }
```

## Tests

```bash
python3 -m unittest discover -s tests -t .     # 701 tests
python3 tools/benchmark.py                      # throughput
```

## License

[MIT](LICENSE) © Саша · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md">中文</a>
