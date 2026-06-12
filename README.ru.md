<div align="center">

# 🛡️ Data Shield AI

### Приватная прослойка между ИИ и пользователем

Маскирует конфиденциальные данные **локально** — до отправки во внешнюю модель.<br/>
Без сети. Без зависимостей. Чистый Python.

<br/>

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-701%20passing-success.svg)](#-тесты)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![Detectors](https://img.shields.io/badge/detectors-52-orange.svg)](#-возможности)

<br/>

<b>🌐 Читать на других языках:</b>
<br/>
<a href="README.md">🇬🇧 English</a> &nbsp;·&nbsp;
<a href="README.ru.md"><b>🇷🇺 Русский</b></a> &nbsp;·&nbsp;
<a href="README.zh-CN.md">🇨🇳 中文</a>

</div>

---

```text
вход   →   Иван Петров, ИНН 7707083893, карта 4111 1111 1111 1111, ключ AKIAIOSFODNN7EXAMPLE
выход  →   [PERSON_1], ИНН [INN_1], карта [CREDIT_CARD_1], ключ [AWS_ACCESS_KEY_1]
```

Когда вы отправляете текст во внешний ИИ, вместе с полезной задачей туда легко
утекают персональные данные, реквизиты и секреты. **Data Shield AI** вырезает их
локально, до отправки, оставляя ИИ только обезличенную задачу.

## 📑 Содержание

- [Возможности](#-возможности)
- [Установка](#-установка)
- [Использование](#-использование)
- [Программный API](#-программный-api)
- [Конфигурация](#-конфигурация)
- [Режимы повышенной полноты](#-режимы-повышенной-полноты)
- [Скорость](#-скорость)
- [Приватность](#-приватность)
- [Тесты](#-тесты)

## ✨ Возможности

- **Имена (PERSON) без ML** — русские отчества, контекст («меня зовут…», «Mr.»,
  «Dear»), пары «Имя Фамилия» из словаря. Холодный старт ~15 мс — не тормозит.
- **Адреса РФ (ADDRESS)** — улицы/проспекты/переулки; почтовый индекс.
- **Россия** — ИНН (контроль 10/12), СНИЛС, паспорт РФ, телефон РФ, ОГРН/ОГРНИП
  (контрольная цифра), КПП, БИК, расчётный счёт, полис ОМС, водительское удост.
- **Международное** — email, телефон, карта (**проверка по Луну**), IBAN
  (mod-97), IPv4/IPv6, MAC, US SSN/EIN, UK NINO, крипто-кошельки ETH/BTC.
- **Секреты** — ключи AWS / OpenAI / Anthropic / GitHub / GitLab / Google /
  Slack / Stripe / HuggingFace / Shopify и др., JWT, приватные ключи, `password=…`.
- **Стабильные плейсхолдеры** — одно значение → один плейсхолдер, поэтому ИИ
  понимает «тот же человек / та же карта», не видя реальных данных.
- **Низкие ложные срабатывания** — контрольные суммы вместо «голых» регулярок.
- **Приватность по умолчанию** — оригиналы только в памяти; отчёт хранит лишь
  солёные хеши.
- **Гибрид** — опциональные ML-плагины (Presidio или лёгкий GLiNER) для
  максимальной полноты по свободным именам/адресам/организациям.
- **Ноль зависимостей.** Python 3.9+. 52 детектора из коробки.

## 📦 Установка

```bash
git clone git@github.com:meloch287/data-shield-ai.git
cd data-shield-ai
bash install.sh        # навык Claude Code + команда `datashield`
```

Либо без установки — прямо из репозитория:

```bash
python3 -m datashield redact --in input.txt
```

## 🚀 Использование

```bash
# Маскировка (основная команда)
echo "мой email a@b.com, ИНН 7707083893" | datashield redact
# -> мой email [EMAIL_1], ИНН [INN_1]

datashield scan  --in dialog.txt    # что найдено (без маскировки)
datashield stats --in dialog.txt    # сводка по типам
datashield detectors                # список всех детекторов
```

<details>
<summary><b>Полезные флаги</b></summary>

| Флаг | Назначение |
|------|-----------|
| `--in / --out` | файл вместо stdin/stdout |
| `--only EMAIL,CREDIT_CARD` | только указанные типы |
| `--exclude IP` | исключить типы |
| `--min-confidence 0.5` | порог уверенности (агрессивнее ловит) |
| `--json` | машинный вывод |
| `--report audit.json` | аудит без сырых значений (только хеши) |
| `--config .datashield.json` | свой конфиг |

</details>

## 🐍 Программный API

```python
from datashield import redact, scan

result = redact("телефон +7 909 123 45 67")
print(result.masked_text)   # 'телефон [PHONE_RU_1]'
print(result.stats)          # {'PHONE_RU': 1}

for f in scan("email a@b.com"):
    print(f.type, f.start, f.end, f.confidence)
```

## ⚙️ Конфигурация

`.datashield.json` в рабочей директории (пример — `.datashield.example.json`):

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

- `allowlist` — значения/домены, которые не маскируются.
- `enabled_detectors` — включить опциональные (`high_entropy`, `names_aggressive`,
  `ml`, `gliner`).
- `disabled_detectors` — выключить детектор по имени или типу.
- `custom_patterns` — свои регулярные выражения.

## 🎯 Режимы повышенной полноты

**Агрессивные имена (без зависимостей)** — маскировать одиночные известные имена
(`Иван`, `John`) ценой возможных омонимов (`Вера`, `Roman`):

```json
{ "enabled_detectors": ["names_aggressive"] }
```

**ML через GLiNER (лёгкий, ONNX на CPU):**

```bash
pip install "data-shield-ai[gliner]"
```
Затем `{ "enabled_detectors": ["gliner"] }`.

**ML через Microsoft Presidio (максимальная полнота):**

```bash
pip install "data-shield-ai[ml]"
python3 -m spacy download en_core_web_lg
```
Затем `{ "enabled_detectors": ["ml"] }`. Без установленных пакетов ядро
продолжает работать как обычно — плагины просто не добавляют находок.

## ⚡ Скорость

Холодный старт ~15 мс, типичный промпт (1–3 КБ) — 1–3 мс. ML-плагины грузят
модель один раз; ядро без зависимостей не требует загрузки моделей вовсе.
Замер: `python3 tools/benchmark.py`.

## 🔒 Приватность

- Полностью локально, сеть не используется.
- Оригиналы держатся только в памяти и стираются при выходе.
- Режим **односторонней редакции** — восстановления оригиналов нет.
- `--report` содержит только тип, позицию и **солёный SHA-256 хеш** значения.

## 🧪 Тесты

```bash
python3 -m unittest discover -s tests -t .
```

701 тест, только stdlib `unittest`, зелёные на Python 3.9–3.13.

## 📄 Лицензия

[MIT](LICENSE) © Саша

<div align="center"><sub>Сделано для приватных ИИ-сценариев · <a href="README.md">English</a> · <a href="README.zh-CN.md">中文</a></sub></div>
