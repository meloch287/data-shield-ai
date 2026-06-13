# Журнал изменений

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).

## [1.4.0] — 2026-06-13

### Добавлено
- **Структурированные входы** (`datashield.structured`): `redact_json` и
  `redact_csv` маскируют значения по детекторам И по «чувствительным» ключам/
  колонкам, сохраняя структуру. CLI: `redact --format json-data|csv`.
- **Пресеты соответствия** (`--preset`): `pci-dss`, `hipaa`, `gdpr`,
  `secrets-only`, `ru-gov`, `minimal` — наборы типов/порог под задачу.
- **Категории и критичность** (`datashield.taxonomy`): каждый тип отнесён к
  категории (contact/person/government_id/financial/health/crypto/network/secret)
  и severity (low/medium/high/critical). Фильтр `--min-severity`; поля
  `category`/`severity` в `report()` и `scan --json`; в выводе `detectors`.
- **TOML-конфиг** (`.datashield.toml`, Python 3.11+) в дополнение к JSON.
- Поля конфигурации: `preset`, `min_severity`.

## [1.3.0] — 2026-06-13

### Добавлено
- **Международные ID** (`datashield/validators_intl.py` + `detectors/intl_ids.py`):
  India Aadhaar (Verhoeff) и PAN, China 居民身份证 (mod-11) и мобильный,
  UK NHS (mod-11) и sort code, US ABA (checksum)/passport/ITIN, EU — Spain
  DNI/NIE, Italy Codice Fiscale, France NIR (mod-97), Germany Steuer-ID,
  Poland PESEL. Сильная валидация → включены по умолчанию; форматно-общие —
  контекстно-зависимые.
- **Сеть/инфра** (`detectors/network.py`): учётки в URL (`scheme://user:pass@`),
  AWS ARN, гео-координаты (по ключевому слову).
- **Ещё секреты**: Twilio, Mailgun, Telegram bot, Discord, SSH public key.
- **75 детекторов, 68 типов** данных из коробки.

### Исправлено
- ReDoS в детекторе `url_credentials` (катастрофический бэктрекинг по длинному
  ряду букв): ограничена длина схемы + `\b`; 2144 мс → 46 мс на 50 КБ.

## [1.2.0] — 2026-06-13

### Добавлено
- **Обратимая редакция** (опционально): `redact(..., reversible=True)` собирает
  vault (замена→оригинал); `result.restore()` и `restore(text, vault)` точно
  восстанавливают оригинал. CLI: `redact --vault file.json` и команда `restore`.
- **Стратегии маскировки** (`--strategy`): `placeholder` (по умолчанию),
  `pseudonym` (детерминированные фейки — карта валидна по Луну, формат сохранён),
  `partial` (`**** **** **** 1111`), `hash` (`[TYPE_<hash>]`), `remove`.
- **Format-preserving генераторы** (`datashield.formats`) — детерминированные
  фейки с сохранением длины/разделителей.
- Поля конфигурации: `strategy`, `pseudonym_key`, `reversible`.

### Инфраструктура
- `py.typed`, конфиги ruff/mypy/coverage; CI: задачи lint и coverage.
- `CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`, шаблоны issue/PR.

## [1.1.0] — 2026-06-13

### Добавлено
- **Детекция имён (PERSON)** без ML — газеттир + эвристики: русские отчества,
  контекст («меня зовут…», «Mr.», «Dear»), пары «Имя Фамилия» из словаря.
  Включена по умолчанию, холодный старт ~15 мс.
- **Агрессивный режим имён** `names_aggressive` (по умолчанию выключен) —
  одиночные известные имена; включается через `enabled_detectors`.
- **Адреса РФ (ADDRESS)** — по ключевым словам улиц; почтовый индекс по слову
  «индекс».
- **Новые идентификаторы:** ОГРН/ОГРНИП (контрольная цифра), КПП, БИК,
  расчётный счёт, полис ОМС, водительское удостоверение РФ, US SSN/EIN,
  UK NINO, крипто-кошельки ETH/BTC.
- **Опциональный плагин GLiNER** (`gliner`) — лёгкая ONNX-альтернатива Presidio.
- Бенчмарк `tools/benchmark.py`, GitHub Actions CI (Python 3.9–3.13).

- **Больше токенов-секретов:** GitHub fine-grained PAT (`github_pat_`), GitLab
  (`glpat-`), HuggingFace (`hf_`), npm, Google OAuth (`GOCSPX-`), DigitalOcean,
  Shopify, Square, SendGrid.
- **52 детектора**, 45 типов данных. Регресс-тесты адверсариал-аудита.

### Исправлено (по итогам адверсариал-аудита)
- Детектор карт больше не матчится внутри hex-токенов (ETH-адреса); отбраковка
  номеров с ведущим нулём и из одной повторяющейся цифры (00000…, 1111…).
- Одиночные слова на «-ич» (Кирпич, Кулич, Москвич) больше не PERSON; короткий
  суффикс распознаётся только в составе ФИО.
- Пары «Имя + частое английское слово» (Mark Down, Grace Period) больше не PERSON.
- Улица-слово как нарицательное («шоссе было пустым») больше не ADDRESS.
- US SSN и UK NINO стали контекстно-зависимыми (нужно ключевое слово рядом) —
  меньше ложных срабатываний на артикулах/тикетах.
- IPv6 со сжатием `::` и 3+ группами теперь распознаётся.
- Карта/СНИЛС/телефон РФ ловятся и с точками-разделителями; добавлен Cisco-MAC.

### Производительность
- `resolve_overlaps` переписан на битовую карту занятости (`bytearray`):
  ~O(n) вместо O(k²). Стресс 2 МБ / 160k находок: 7.2 с → 1.65 с.

## [1.0.0] — 2026-06-13

### Добавлено
- Первый релиз: локальная редакция конфиденциальных данных.
- РФ: ИНН, СНИЛС, паспорт РФ, телефон РФ.
- Международное: email, телефон, карта (Луна), IBAN (mod-97), IP, MAC.
- Секреты: ключи AWS/OpenAI/Anthropic/GitHub/Google/Slack/Stripe, JWT,
  приватные ключи, пароли.
- Типизированные стабильные плейсхолдеры, аудит-отчёт с солёными хешами.
- Навык Claude Code + Codex + CLI + Python API. Ноль зависимостей.
