<div align="center">

# 🛡️ Data Shield AI

Локальная редакция ПДн/секретов. Маскирует конфиденциальные данные до того, как текст покинет машину.

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-701%20passing-success.svg)](#тесты)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#метрики)
[![Detectors](https://img.shields.io/badge/detectors-75-orange.svg)](#каталог-детекторов)

<a href="README.md">🇬🇧 English</a> &nbsp;·&nbsp;
<a href="README.ru.md"><b>🇷🇺 Русский</b></a> &nbsp;·&nbsp;
<a href="README.zh-CN.md">🇨🇳 中文</a>

</div>

```text
вход   →   Иван Петров, ИНН 7707083893, карта 4111 1111 1111 1111, ключ AKIAIOSFODNN7EXAMPLE
выход  →   [PERSON_1], ИНН [INN_1], карта [CREDIT_CARD_1], ключ [AWS_ACCESS_KEY_1]
```

Чистый Python stdlib, без зависимостей, без сети. 75 детекторов, 68 типов данных. Одно значение → один плейсхолдер; оригиналы не пишутся на диск.

- [Конвейер](#конвейер)
- [Архитектура](#архитектура)
- [Каталог детекторов](#каталог-детекторов)
- [Модель уверенности](#модель-уверенности)
- [Разбор пересечений](#разбор-пересечений)
- [Алгоритмы валидации](#алгоритмы-валидации)
- [Стратегии и обратимость](#стратегии-и-обратимость)
- [Метрики](#метрики)
- [Модель приватности](#модель-приватности)
- [Установка / Использование / API](#установка)
- [Тесты](#тесты)

## Конвейер

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

Каждый детектор отдаёт `Finding(type, start, end, value, confidence, detector)`. Движок не заглядывает внутрь детектора — он видит только `Finding`, поэтому добавление детектора (включая ML-плагины) не требует правок движка.

## Архитектура

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

| Модуль | Ответственность | LOC* |
|--------|-----------------|-----:|
| `engine.py` | оркестрация, разбор пересечений, отчёт | ~140 |
| `detectors/base.py` | `Finding`, regex- и context-детекторы | ~140 |
| `detectors/{regex_intl,ru,extra,secrets,addresses,names}.py` | 75 детекторов | ~600 |
| `detectors/{ml,gliner}_plugin.py` | опциональные ленивые ML-адаптеры | ~200 |
| `validators.py` | контроль Luhn / ИНН / СНИЛС / IBAN / ОГРН | ~110 |
| `masking.py` | выдача стабильных типизированных плейсхолдеров | ~60 |
| `config.py` · `api.py` · `cli.py` | конфиг, публичный API, CLI | ~340 |

<sub>* ядро суммарно: <b>1665</b> строк в 21 файле; тесты: <b>4725</b> строк в 18 файлах.</sub>

## Каталог детекторов

75 детекторов → 68 типов плейсхолдеров. `conf` = уверенность; `a→b` = база→буст при ключевом слове в контексте (окно 25 символов). Ниже порога по умолчанию `0.70` находка отбрасывается, поэтому контекстно-зависимые ID не срабатывают на голых числах.

**Международные**

| детектор | тип | conf | валидация |
|----------|-----|:----:|-----------|
| `email` | EMAIL | 0.98 | — |
| `phone_intl` | PHONE | 0.80 | нужен ведущий `+` |
| `credit_card` | CREDIT_CARD | 0.90 | Луна + отбраковка 0-lead/повторов |
| `iban` | IBAN | 0.95 | mod-97 |
| `ipv4` / `ipv6` | IP | 0.85 / 0.80 | диапазон октетов / форма `::` |
| `mac` / `mac_cisco` | MAC | 0.85 | — |

**Россия**

| детектор | тип | conf | валидация |
|----------|-----|:----:|-----------|
| `inn` | INN | var→0.95 | контрольная цифра (10/12) |
| `snils` | SNILS | 0.80→0.95 | контрольная сумма |
| `passport_ru` | PASSPORT_RU | 0.40→0.90 | контекст |
| `phone_ru` | PHONE_RU | 0.85 | — |
| `ogrn` / `ogrnip` | OGRN/OGRNIP | 0.85 | контрольная цифра |
| `kpp` `bic` `bank_account` `oms_policy` `driver_license_ru` | … | 0.40–0.55→0.90+ | контекст |
| `address_ru` | ADDRESS | 0.78 | слово-улица + заглавное название |
| `postal_code_ru` | POSTAL_CODE | 0.30→0.85 | контекст (`индекс`) |

**Личность / крипто**

| детектор | тип | conf | валидация |
|----------|-----|:----:|-----------|
| `us_ssn` `uk_nino` | US_SSN / UK_NINO | 0.50→0.92 | контекстно-зависимые |
| `us_ein` | US_EIN | 0.40→0.90 | контекст |
| `eth_address` | ETH_ADDRESS | 0.95 | `0x` + 40 hex |
| `btc_address` | BTC_ADDRESS | 0.78 | base58 / bech32 |
| `names` | PERSON | эвристика | отчество · контекст · пара из словаря |

**Секреты** (0.90–0.99, отличимые префиксы)

`aws_access_key` `aws_secret` `anthropic_key` `openai_key` `github_token` `github_pat` `gitlab_token` `huggingface_token` `npm_token` `google_oauth_secret` `digitalocean_token` `shopify_token` `square_token` `google_api_key` `slack_token` `stripe_key` `sendgrid_key` `jwt` `private_key` `password` `secret_assignment`

**Опциональные** (по умолчанию выкл): `high_entropy` (0.75), `names_aggressive` (одиночные имена), `ml` (Presidio), `gliner` (ONNX NER).

## Модель уверенности

Каждая находка несёт уверенность в `[0,1]`. Движок оставляет `confidence ≥ min_confidence` (по умолчанию `0.70`).

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

Правило: структурно неоднозначное значение (число из 9–12 цифр, код `NNN-NN-NNNN`) остаётся **ниже** порога, пока рядом не появится ключевое слово (`ИНН`, `СНИЛС`, `SSN`, `БИК`…). Поэтому номера заказов и артикулы не маскируются, а реальные подписанные ID — маскируются.

## Разбор пересечений

Детекторы работают независимо и дают пересекающиеся кандидаты (`+7…` ловят и `phone_ru`, и `phone_intl`; цифровой кусок внутри ETH-адреса ловит `credit_card`). Разбор — жадный по приоритету:

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

`occupied.find` и присваивание среза работают на C-уровне, поэтому проход ~O(n) по длине текста вместо O(k²) попарных проверок интервалов. Результат на входе 2 МБ с 160 000 различных находок: **7.2 с → 1.64 с**.

## Алгоритмы валидации

Контрольные суммы заменяют наивный матч регуляркой и давят ложные срабатывания.

| алгоритм | применяется к | проверка |
|----------|---------------|----------|
| Луна | банковские карты | `Σ цифр (каждая 2-я удвоена) mod 10 == 0`, отбраковка 0-lead/одинаковых |
| ИНН-10 | ИНН юрлица | взвеш. сумма `mod 11 mod 10 == d[9]` |
| ИНН-12 | ИНН физлица | две контрольные цифры |
| СНИЛС | пенсионный | `Σ d[i]·(9-i) mod 101` → контроль |
| IBAN | банк. счёт | 4 символа в хвост, буквы→числа, `mod 97 == 1` |
| ОГРН/ОГРНИП | рег. компании | `int(первые n) mod (11/13) mod 10 == последняя` |

## Стратегии и обратимость

`redact()` заменяет каждую находку через **стратегию**. С `reversible=True`
собирается vault (`замена → оригинал`), чтобы размаскировать ответ ИИ.

| стратегия | пример | обратима |
|-----------|--------|:--------:|
| `placeholder` (по умолч.) | `[CARD_1]` | да |
| `pseudonym` | `4574 9172 3643 9348` (фейк, валиден по Луну, форма сохранена) | да |
| `partial` | `**** **** **** 1111` | нет |
| `hash` | `[CARD_3f9a1c2b80]` | да |
| `remove` | `` (удаление) | нет |

```python
r = redact("карта 4111 1111 1111 1111", strategy="pseudonym", reversible=True)
r.masked_text   # 'карта 4574 9172 3643 9348'  — фейк, проходит Луна
r.restore()     # 'карта 4111 1111 1111 1111'  — точная инверсия
```

CLI: `datashield redact --strategy pseudonym --vault v.json`, затем
`… | datashield restore --vault v.json`. Vault хранит оригиналы — держите локально.

## Метрики

Одно ядро, Python 3.14, прогретый процесс. Пропускная способность линейна по размеру входа и постоянна **~1.05 MB/с**; холодный старт (импорт → первый redact) **~15 мс** (против секунд на загрузку ML-модели).

```mermaid
xychart-beta
  title "Latency vs input size (lower is better)"
  x-axis ["1KB", "4KB", "16KB", "64KB", "256KB", "1MB"]
  y-axis "ms per call" 0 --> 1000
  bar [1.05, 3.9, 15.4, 61, 243, 955]
```

| вход | мс/вызов | MB/с |
|-----:|---------:|-----:|
| 1 КБ | 1.05 | 1.02 |
| 4 КБ | 3.90 | 1.03 |
| 16 КБ | 15.4 | 1.04 |
| 64 КБ | 61.0 | 1.05 |
| 256 КБ | 243 | 1.05 |
| 1 МБ | 955 | 1.05 |

```mermaid
xychart-beta
  title "Overlap resolution, 2MB / 160k findings (seconds)"
  x-axis ["before: O(k^2)", "after: O(n)"]
  y-axis "seconds" 0 --> 8
  bar [7.2, 1.64]
```

| метрика | значение |
|---------|----------|
| Детекторов / типов | 75 / 68 |
| Включено по умолчанию | 48 |
| Холодный старт | ~15 мс |
| Пропускная способность | ~1.05 MB/с |
| Тесты | **701** (stdlib unittest), зелёные на Python 3.9–3.13 |
| Время прогона тестов | ~6.1 с |
| Зависимости в рантайме | **0** |
| Размер ядра | 1665 строк / 21 файл |

Детекторы прошли параллельный адверсариал-аудит (13 агентов): найдено и исправлено 13 проблем precision/recall/DoS, каждая зафиксирована регресс-тестом (`tests/test_adversarial_regression.py`).

## Модель приватности

```mermaid
flowchart LR
  V["original value"] -->|in memory only| PH["placeholder TYPE_n"]
  V -. "--report only" .-> H["salted SHA-256<br/>(truncated)"]
  V -.->|never persisted| X["disk x / network x"]
```

- Односторонняя редакция — нет пути восстановления, нет хранилища.
- `--report` пишет `{type, start, end, confidence, detector, value_sha256, preview}` — никогда сырое значение.
- Тест приватности гарантирует, что оригиналы не появляются ни в одном отчёте.

## Установка

```bash
git clone git@github.com:meloch287/data-shield-ai.git && cd data-shield-ai
bash install.sh        # навык Claude Code + команда `datashield`
# или без установки:
python3 -m datashield redact --in input.txt
```

### Использование

```bash
echo "мой email a@b.com, ИНН 7707083893" | datashield redact   # -> [EMAIL_1], ИНН [INN_1]
datashield scan  --in f.txt        # находки, без маскировки
datashield stats --in f.txt        # счётчики по типам
datashield detectors               # список всех 52
```

Флаги: `--in/--out` · `--only T1,T2` · `--exclude T` · `--min-confidence X` · `--json` · `--report audit.json` · `--config path`.

### API

```python
from datashield import redact, scan
redact("телефон +7 909 123 45 67").masked_text   # 'телефон [PHONE_RU_1]'
[(f.type, f.confidence) for f in scan("a@b.com")]
```

### Конфиг (`.datashield.json`)

```json
{ "min_confidence": 0.7, "allowlist": ["example.com"],
  "enabled_detectors": ["names_aggressive", "gliner"],
  "custom_patterns": [{"name":"employee_id","type":"EMPLOYEE_ID","pattern":"EMP-\\d{6}","confidence":0.9}] }
```

## Тесты

```bash
python3 -m unittest discover -s tests -t .     # 701 тест
python3 tools/benchmark.py                      # пропускная способность
```

## Лицензия

[MIT](LICENSE) © Саша · <a href="README.md">English</a> · <a href="README.zh-CN.md">中文</a>
