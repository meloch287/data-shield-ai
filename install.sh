#!/usr/bin/env bash
# Установка Data Shield AI как навыка Claude Code и команды `datashield`.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="${HOME}/.claude/skills"
TARGET_DIR="${SKILLS_DIR}/data-shield-ai"
BIN_DIR="${HOME}/.local/bin"

echo "Data Shield AI — установка"
echo "  источник:  ${SOURCE_DIR}"

# 1. Проверка Python.
if ! command -v python3 >/dev/null 2>&1; then
  echo "Ошибка: нужен python3 (3.9+)." >&2
  exit 1
fi

# 2. Линкуем навык в каталог навыков Claude Code.
mkdir -p "${SKILLS_DIR}"
if [ -e "${TARGET_DIR}" ] && [ ! -L "${TARGET_DIR}" ]; then
  echo "Внимание: ${TARGET_DIR} уже существует и не является ссылкой — пропускаю." >&2
else
  ln -sfn "${SOURCE_DIR}" "${TARGET_DIR}"
  echo "  навык:     ${TARGET_DIR} -> ${SOURCE_DIR}"
fi

# 3. Подключаем команду `datashield`.
mkdir -p "${BIN_DIR}"
ln -sfn "${SOURCE_DIR}/bin/datashield" "${BIN_DIR}/datashield"
chmod +x "${SOURCE_DIR}/bin/datashield"
echo "  команда:   ${BIN_DIR}/datashield"

# 4. Быстрая самопроверка.
if echo "проверка a@b.com" | python3 "${SOURCE_DIR}/bin/datashield" redact | grep -q "\[EMAIL_1\]"; then
  echo "  самопроверка: OK"
else
  echo "  самопроверка: НЕ ПРОЙДЕНА" >&2
  exit 1
fi

echo
echo "Готово."
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) echo "Добавьте в PATH:  export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
echo "Проверка: echo 'мой email a@b.com' | datashield redact"
