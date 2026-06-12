# Data Shield AI

**Приватная прослойка между ИИ и пользователем.** Локальный офлайн-фильтр,
который находит конфиденциальные данные в тексте и заменяет их на типизированные
плейсхолдеры (`[EMAIL_1]`, `[INN_1]`, `[CARD_2]`) **до** отправки во внешнюю
модель. Без сети, без зависимостей, на чистой Python stdlib.

```
вход:   ИНН 7707083893, карта 4111 1111 1111 1111, ключ AKIAIOSFODNN7EXAMPLE
выход:  ИНН [INN_1], карта [CREDIT_CARD_1], ключ [AWS_ACCESS_KEY_1]
```

## Зачем

Когда вы отправляете текст во внешний ИИ, вместе с полезной задачей туда легко
утекают персональные данные, реквизиты и секреты. Data Shield AI вырезает их
локально, до отправки, оставляя ИИ только обезличенную задачу.

## Возможности

- **Россия:** ИНН (контроль 10/12), СНИЛС (контрольная сумма), паспорт РФ,
  телефон РФ.
- **Международное:** email, телефон, банковская карта (**проверка по Луну**,
  а не «любые 16 цифр»), IBAN (mod-97), IPv4/IPv6, MAC.
- **Секреты:** ключи AWS/OpenAI/Anthropic/GitHub/Google/Slack/Stripe, JWT,
  приватные ключи, `password=…`/`пароль: …`.
- **Стабильные плейсхолдеры:** одно значение → один плейсхолдер, поэтому ИИ
  понимает «тот же человек / та же карта», не видя реальных данных.
- **Низкие ложные срабатывания:** контрольные суммы вместо «голых» регулярок.
- **Приватность по умолчанию:** оригиналы только в памяти; отчёт хранит лишь
  солёные хеши.
- **Гибрид:** опциональный ML-плагин (Presidio) для свободных имён/адресов.
- **Ноль зависимостей.** Python 3.9+.

## Установка

```bash
git clone git@github.com:meloch287/data-shield-ai.git
cd data-shield-ai
bash install.sh        # навык Claude Code + команда `datashield`
```

Либо без установки — прямо из репозитория:

```bash
python3 -m datashield redact --in input.txt
```

## Использование

```bash
# Маскировка
echo "мой email a@b.com, ИНН 7707083893" | datashield redact
# -> мой email [EMAIL_1], ИНН [INN_1]

# Что найдено (без маскировки)
datashield scan --in dialog.txt

# Сводка по типам
datashield stats --in dialog.txt

# Список детекторов
datashield detectors
```

### Полезные флаги

| Флаг | Назначение |
|------|-----------|
| `--in / --out` | файл вместо stdin/stdout |
| `--only EMAIL,CREDIT_CARD` | только указанные типы |
| `--exclude IP` | исключить типы |
| `--min-confidence 0.5` | порог уверенности (агрессивнее ловит) |
| `--json` | машинный вывод |
| `--report audit.json` | аудит без сырых значений (только хеши) |
| `--config .datashield.json` | свой конфиг |

## Программный API

```python
from datashield import redact, scan

result = redact("телефон +7 909 123 45 67")
print(result.masked_text)   # 'телефон [PHONE_RU_1]'
print(result.stats)          # {'PHONE_RU': 1}

for f in scan("email a@b.com"):
    print(f.type, f.start, f.end, f.confidence)
```

## Конфигурация

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
- `enabled_detectors` — включить опциональные (`high_entropy`, `ml`).
- `disabled_detectors` — выключить детектор по имени или типу.
- `custom_patterns` — свои регулярные выражения.

## Гибридный режим (ML)

Распознавание свободных имён/адресов через Microsoft Presidio:

```bash
pip install "data-shield-ai[ml]"
python3 -m spacy download en_core_web_lg
```
Затем в `.datashield.json`: `"enabled_detectors": ["ml"]`. Без Presidio ядро
продолжает работать как обычно.

## Приватность

- Полностью локально, сеть не используется.
- Оригиналы держатся только в памяти и стираются при выходе.
- Режим **односторонней редакции** — восстановления оригиналов нет.
- `--report` содержит только тип, позицию и **солёный SHA-256 хеш** значения.

## Тесты

```bash
python3 -m unittest discover -s tests -t .
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
