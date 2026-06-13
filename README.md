<div align="center">

# 🛡️ Data Shield AI

Local PII/secret redaction layer. Masks confidential data before text leaves the machine.

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-1956%20passing-success.svg)](#tests)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#footprint)
[![Detectors](https://img.shields.io/badge/detectors-90-orange.svg)](#detector-catalog)

<a href="README.md"><b>🇬🇧 English</b></a> &nbsp;·&nbsp;
<a href="README.ru.md">🇷🇺 Русский</a> &nbsp;·&nbsp;
<a href="README.zh-CN.md">🇨🇳 中文</a>

</div>

```text
in   →   Ivan Petrov, INN 7707083893, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE
out  →   [PERSON_1], INN [INN_1], card [CREDIT_CARD_1], key [AWS_ACCESS_KEY_1]
```

Pure Python stdlib, no dependencies, no network. 90 detectors, 83 data types. Same value → same placeholder; originals never written to disk.

- [Pipeline](#pipeline)
- [Architecture](#architecture)
- [Detector catalog](#detector-catalog)
- [Confidence model](#confidence-model)
- [Overlap resolution](#overlap-resolution)
- [Validation algorithms](#validation-algorithms)
- [Strategies & reversibility](#strategies--reversibility)
- [Presets and structured input](#presets-and-structured-input)
- [Metrics](#metrics)
- [Privacy model](#privacy-model)
- [Install / Usage / API](#install)
- [Integrations](#integrations)
- [Tests](#tests)

## Pipeline

```mermaid
flowchart LR
  subgraph DET["90 detectors run independently"]
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
| `detectors/{regex_intl,ru,extra,intl_ids,network,secrets,addresses,names}.py` | the 90 detectors | ~900 |
| `detectors/{ml,gliner}_plugin.py` | optional lazy ML adapters | ~200 |
| `validators.py` · `validators_intl.py` | Luhn / INN / IBAN / Verhoeff / mod-11/97 | ~280 |
| `strategies.py` · `formats.py` · `masking.py` | strategies, pseudonyms, placeholders | ~250 |
| `compliance.py` · `taxonomy.py` · `presets.py` | severity, regulations, presets | ~180 |
| `structured.py` · `normalize.py` · `streaming.py` · `batch.py` | structured/normalize/scale | ~280 |
| `integrations/*` | MCP, HTTP, logging filter | ~250 |
| `config.py` · `api.py` · `cli.py` | config, public API, CLI | ~600 |

<sub>* core total: <b>3400+</b> lines across 37 files; tests: <b>17000+</b> lines across 65 files.</sub>

## Detector catalog

90 detectors → 83 placeholder types. `conf` = confidence; `a→b` = base→boosted when a keyword is in context (25-char window). Below the default threshold `0.70` a finding is dropped, so context-gated IDs do not fire on bare numbers.

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

**World national IDs** (checksum-validated)

| detector | type | conf | validation |
|----------|------|:----:|------------|
| `cpf_br` / `cnpj_br` (Brazil) | CPF_BR / CNPJ_BR | 0.85 / 0.88 | mod-11 |
| `curp_mx` (Mexico) | CURP_MX | 0.90 | check digit |
| `rrn_kr` (Korea) | RRN_KR | 0.40→0.92 | mod-11 + context¹ |
| `vin` | VIN | 0.40→0.90 | ISO 3779 + context¹ |
| `sin_ca` `tfn_au` `mynumber_jp` (CA/AU/JP) | … | 0.40→0.90 | checksum + context |

¹ A lone mod-11 / ISO-3779 check passes ~9% of random 13-digit / 17-char tokens, so RRN and VIN require a keyword nearby (`주민등록번호`/`RRN`, `VIN`/`chassis`/`номер кузова`). TRON stays default-on — base58check (double-SHA256) is decisive.

**Network / crypto**

`url_credentials` (masks `user:pass` in `scheme://…@`) · `aws_arn` · `geo_coord` · `eth_address` · `btc_address` · `tron_address` · `solana_address`.

**Secrets** (0.85–0.99, distinctive prefixes)

`aws_access_key` `aws_secret` `anthropic_key` `openai_key` `github_token` `github_pat` `gitlab_token` `huggingface_token` `npm_token` `google_oauth_secret` `digitalocean_token` `shopify_token` `square_token` `google_api_key` `slack_token` `stripe_key` `stripe_webhook` `sendgrid_key` `twilio_sid` `mailgun_key` `telegram_bot` `discord_token` `ssh_pubkey` `vault_token` `doppler_token` `planetscale_token` `linear_token` `jwt` `private_key` `password` `secret_assignment`

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

## Presets and structured input

**Compliance presets** restrict detection to the types a regime cares about:

| preset | scope |
|--------|-------|
| `pci-dss` | financial + secrets |
| `hipaa` | health + person + government IDs + contact |
| `gdpr` | broad personal data |
| `secrets-only` | keys/tokens/passwords |
| `ru-gov` | Russian government requisites |
| `minimal` | only confidence ≥ 0.9 |

```bash
datashield redact --preset pci-dss          # mask cards & secrets only
datashield redact --min-severity critical   # mask only critical types
```

Every type has a **category** and **severity** (low/medium/high/critical), shown in
`datashield detectors`, `scan --json`, and the audit report, and usable via
`--min-severity`.

**Structured input** masks values while keeping the structure intact — by detector
*and* by sensitive key/column/tag name (`password`, `token`, `ssn`, …). Formats:
`json-data`, `ndjson` (JSON Lines), `csv`, `xml` — all stdlib, no parser deps:

```bash
echo '{"name":"Ivan","password":"hunter2","age":30}' | datashield redact --format json-data
# {"name":"[PERSON_1]","password":"[REDACTED]","age":30}
datashield redact --format ndjson --in events.jsonl  # mask each JSON line, structure kept
datashield redact --format csv    --in people.csv    # sensitive columns + per-cell detection
datashield redact --format xml    --in export.xml    # node text + attributes; <password>→[REDACTED]
```

NDJSON masks each line independently (an invalid line is masked as plain text — raw
data is never emitted). XML rejects `DOCTYPE`/`ENTITY` (no entity-expansion) and is
depth-bounded. The same helpers are importable: `from datashield import redact_ndjson,
redact_xml, redact_format`.

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
| Detectors / types | 90 / 83 |
| Default-on detectors | 86 |
| **Precision / Recall / F1** | **1.00 / 1.00 / 1.00** (labeled eval corpus, 0 FP) |
| Cold start | ~15 ms |
| Throughput | ~1.05 MB/s |
| Tests | **1956** (stdlib unittest), green on Python 3.9–3.13 |
| <a name="footprint"></a>Runtime dependencies | **0** |

Quality is measured, not asserted: `tools/eval/evaluate.py` runs the engine over a
labeled corpus (`tools/eval/corpus.jsonl`, positives + decoys) and
`tests/test_eval_metrics.py` gates precision/recall/F1 ≥ 0.95 in CI. Version strings
(`1.2.3.4`) and long OIDs are suppressed for the IPv4 detector. Known inherent
ambiguities beyond the corpus (a standalone 4-component OID, or a hash split into
colon-separated hex pairs) can still over-mask as IP/MAC — cosmetic, never a leak.

Detectors were hardened by parallel adversarial audits: precision / recall / DoS
issues (including two ReDoS) were found and fixed, each locked by a regression test
(`tests/test_adversarial_regression.py`).

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
datashield detectors               # list all 75
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

## Integrations

All stdlib, no extra dependencies.

```bash
datashield mcp                      # MCP server (stdio) — agents call redact/scan
datashield serve --port 8765        # HTTP: POST /redact, /scan ; GET /health
datashield check  path/to/files     # exit 1 if confidential data found (CI gate)
```

```python
# Mask confidential data in application logs
import logging
from datashield.integrations.logging_filter import RedactingFilter
logging.getLogger().addFilter(RedactingFilter())
```

- **MCP:** register `datashield mcp` (or the `datashield-mcp` entry point) as an MCP
  server; it exposes `redact` and `scan` tools so any agent masks data before it
  reaches an external model.
- **pre-commit:** add this repo as a hook (`.pre-commit-hooks.yaml`, id
  `data-shield-ai`) to block commits that contain PII/secrets.
- **GitHub Action:** `action.yml` scans a repo and fails the build on findings.

## Tests

```bash
python3 -m unittest discover -s tests -t .     # 1956 tests
python3 tools/benchmark.py                      # throughput
python3 tools/eval/evaluate.py                  # precision/recall on the corpus
```

## License

[MIT](LICENSE) © Саша · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md">中文</a>
