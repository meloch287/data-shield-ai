---
name: data-shield-ai
description: >-
  Use BEFORE sending any user-provided text that may contain confidential data
  to an external AI or third-party API. Locally masks sensitive data — emails,
  phone numbers, bank cards, IBAN, IP/MAC, API keys and tokens (AWS, OpenAI,
  Anthropic, GitHub, Google, Slack, Stripe), JWT, private keys, passwords, and
  Russian government IDs (ИНН, СНИЛС, паспорт РФ) — replacing them with stable
  typed placeholders like [EMAIL_1]. Fully offline, zero dependencies. Trigger
  whenever a prompt, document, log, or dataset is about to leave the machine,
  or when the user asks to redact, anonymize, scrub, mask, or sanitize text.
---

# Data Shield AI — приватная прослойка между ИИ и пользователем

Локальный офлайн-фильтр. Находит конфиденциальные данные в тексте и заменяет их
на типизированные плейсхолдеры (`[EMAIL_1]`, `[INN_1]`, `[CARD_2]`) **до** того,
как текст уйдёт во внешнюю модель. Чистая Python stdlib — установка не нужна.

## Когда применять

Перед каждой отправкой во внешний ИИ/API текста, который может содержать:
персональные данные, ИНН/СНИЛС/паспорт РФ, банковские карты, IBAN, IP/MAC,
API-ключи и токены, JWT, приватные ключи, пароли. Также — когда пользователь
просит «замаскируй / обезличь / убери персональные данные / sanitize».

## Как использовать (агенту)

1. Перед отправкой прогони текст через редактор:
   ```bash
   python3 -m datashield redact --in input.txt --out masked.txt
   # или через stdin:
   echo "$TEXT" | python3 -m datashield redact
   ```
2. Отправляй во внешнюю модель **только** содержимое `masked.txt`.
3. Хочешь сначала увидеть, что найдено (без маскировки):
   ```bash
   python3 -m datashield scan --in input.txt
   ```

Если пакет установлен (см. install.sh), доступна короткая команда `datashield`.

## Команды

| Команда | Назначение |
|---------|-----------|
| `datashield redact` | замаскировать текст (stdin/файл → stdout/файл) |
| `datashield scan`   | показать найденные данные без маскировки |
| `datashield stats`  | сводка по типам найденного |
| `datashield detectors` | список детекторов и их статус |

Полезные флаги `redact`/`scan`: `--only EMAIL,CREDIT_CARD`, `--exclude IP`,
`--min-confidence 0.5`, `--json`, `--report audit.json`, `--config .datashield.json`.

## Программный API

```python
from datashield import redact
result = redact("мой email a@b.com, ИНН 7707083893")
print(result.masked_text)   # 'мой email [EMAIL_1], ИНН [INN_1]'
print(result.stats)          # {'EMAIL': 1, 'INN': 1}
```

## Установка

```bash
bash install.sh
```
Скрипт скопирует навык в `~/.claude/skills/data-shield-ai` и подключит команду
`datashield`. Для Codex см. `AGENTS.md`.

## Гарантии приватности

- Обработка полностью локальная, сеть не используется.
- Оригиналы держатся только в оперативной памяти и стираются при выходе.
- Отчёт `--report` содержит только типы, позиции и **солёные SHA-256 хеши** —
  сырые значения не сохраняются никогда.
- Режим односторонней редакции: восстановления оригиналов нет.

## Опционально: ML и high-entropy

Распознавание свободных имён/адресов (Presidio) и детектор высокой энтропии
выключены по умолчанию. Включить — через `.datashield.json`:
```json
{ "enabled_detectors": ["high_entropy", "ml"] }
```
ML требует `pip install presidio-analyzer presidio-anonymizer spacy` и модели;
без них ядро продолжает работать.
