# Data Shield AI — инструкция для агентов (Codex/Claude и др.)

Локальный фильтр приватности. Маскирует конфиденциальные данные **до** отправки
во внешний ИИ/API. Без сетевых вызовов, без зависимостей (чистая Python stdlib).

## Правило

Перед тем как отправить во внешнюю модель текст пользователя, который может
содержать персональные данные, ключи или пароли — прогони его через `datashield`
и отправляй только замаскированный результат.

## Быстрый старт

```bash
# маскировка
echo "$TEXT" | python3 -m datashield redact

# из файла в файл
python3 -m datashield redact --in input.txt --out masked.txt

# что найдено (без маскировки)
python3 -m datashield scan --in input.txt --json
```

Запускать из корня репозитория `data-shield-ai` (где лежит пакет `datashield/`),
либо установить через `bash install.sh` и пользоваться командой `datashield`.

## Коды возврата

- `0` — успех (в т. ч. если ничего не найдено)
- `1` — ошибка ввода-вывода/конфигурации
- `2` — ошибка использования (например, неизвестный тип в `--only`)

## Программный API

```python
from datashield import redact, scan
masked = redact(text).masked_text
findings = scan(text)          # список Finding(type, start, end, confidence, ...)
```

## Конфигурация

Файл `.datashield.json` в рабочей директории (или `--config путь`):

```json
{
  "min_confidence": 0.7,
  "placeholder_template": "[{type}_{n}]",
  "allowlist": ["example.com"],
  "disabled_detectors": [],
  "enabled_detectors": ["high_entropy", "names_aggressive"],
  "custom_patterns": [
    {"name": "employee_id", "type": "EMPLOYEE_ID", "pattern": "EMP-\\d{6}", "confidence": 0.9}
  ]
}
```
