#!/usr/bin/env python3
"""Генерирует размеченный eval-корпус tools/eval/corpus.jsonl (детерминированно).

Каждая строка: {"text": ..., "types": [полный набор типов, которые ДОЛЖНЫ быть
найдены]}. Пустой types — «ловушка» (ничего маскировать нельзя). Валидные образцы
строятся через контрольные суммы, чтобы быть настоящими. Секреты в корпус не
кладём (push-protection) — они проверяются в tests/test_generative.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datashield.validators import luhn_check  # noqa: E402
from datashield.validators_intl import verhoeff_check  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.jsonl")


def luhn_complete(body: str) -> str:
    for d in range(10):
        if luhn_check(body + str(d)):
            return body + str(d)
    raise AssertionError


def aadhaar(body11: str) -> str:
    for d in range(10):
        if verhoeff_check(body11 + str(d)):
            return body11 + str(d)
    raise AssertionError


def china_id(base17: str) -> str:
    w = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    codes = "10X98765432"
    return base17 + codes[sum(int(base17[i]) * w[i] for i in range(17)) % 11]


CARD = luhn_complete("411111111111111")        # Visa-like, valid
CARD2 = luhn_complete("550000555555555")
AADH = aadhaar("23412341234")
CN_ID = china_id("11010119900307123")

# (text, types) — types = полный набор ожидаемых
EXAMPLES = [
    # --- positives ---
    ("Напишите мне на ivan.petrov@example.com сегодня", ["EMAIL"]),
    ("Контакт: maria-smith@sub.example.co.uk", ["EMAIL"]),
    ("Звоните +7 916 123 45 67 после обеда", ["PHONE_RU"]),
    ("Тел 8 (495) 123-45-67 рабочий", ["PHONE_RU"]),
    ("Call me at +1 415 555 0132 tonight", ["PHONE"]),
    (f"Оплата картой {CARD[:4]} {CARD[4:8]} {CARD[8:12]} {CARD[12:]}", ["CREDIT_CARD"]),
    (f"card {CARD2}", ["CREDIT_CARD"]),
    ("Счёт IBAN GB82 WEST 1234 5698 7654 32", ["IBAN"]),
    ("ИНН 7707083893 организации", ["INN"]),
    ("идентификатор 500100732259 в базе", ["INN"]),
    ("СНИЛС 112-233-445 95 в анкете", ["SNILS"]),
    ("ОГРН 1027700132195 в реестре", ["OGRN"]),
    ("сервер 192.168.10.50 в сети", ["IP"]),
    ("узел 2001:db8::8a2e:370:7334 онлайн", ["IP"]),
    ("устройство 00:1A:2B:3C:4D:5E подключено", ["MAC"]),
    (f"Aadhaar {AADH}", ["AADHAAR"]),
    ("PAN ABCDE1234F выдан", ["PAN_IN"]),
    (f"身份证 {CN_ID}", ["CHINA_ID"]),
    ("DNI 12345678Z", ["DNI_ES"]),
    ("Codice Fiscale RSSMRA85T10A562S", ["CODICE_FISCALE"]),
    ("SSN: 123-45-6789", ["US_SSN"]),
    ("NHS 9434765919 record", ["NHS_UK"]),
    ("routing 021000021 confirmed", ["ABA_ROUTING"]),
    ("Договор подписал Иванов Иван Иванович вчера", ["PERSON"]),
    ("Меня зовут Сергей, перезвоните", ["PERSON"]),
    ("Dear John, please review", ["PERSON"]),
    ("Адрес: ул. Ленина, дом 5", ["ADDRESS"]),
    ("живёт на проспекте Мира 12", ["ADDRESS"]),
    ("кошелёк 0x52908400098527886E0F7030069857D2E4169EE7", ["ETH_ADDRESS"]),
    ("db postgres://user:secretpass@host:5432/db", ["URL_CREDENTIALS"]),
    # --- multi-type ---
    ("Иван Петров, email ivan@example.com, ИНН 7707083893", ["PERSON", "EMAIL", "INN"]),
    (f"карта {CARD2}, тел +7 916 000 11 22", ["CREDIT_CARD", "PHONE_RU"]),
    ("Клиент maria@example.com по адресу ул. Гагарина 3", ["EMAIL", "ADDRESS"]),
    # --- decoys (ничего не должно сработать) ---
    ("номер заказа 1234567812345670 готов", []),
    ("трекинг 00000000000000 отправлен", []),
    ("версия сборки 1.2.3.4 финальная", []),
    ("встреча в 12:34:56 по МСК", []),
    ("артикул 123-45-6789 на складе", []),  # SSN-форма без ключевого слова
    ("код AB123456C в каталоге", []),       # NINO-форма без ключевого слова
    ("Кирпич упал со стены", []),
    ("Mark Down the price now", []),
    ("Шоссе было пустым совсем", []),
    ("число 7707083893 просто так", []),    # ИНН-10 без ключевого слова
    ("Большой Театр на площади", []),
    ("commit 0xabcdef1234567890abcdef1234567890abcdef12 merged", ["ETH_ADDRESS"]),
    ("обычное предложение без каких-либо данных", []),
    ("The quick brown fox jumps over the lazy dog", []),
    ("Москва и Санкт-Петербург — большие города", []),
]


def main() -> None:
    with open(OUT, "w", encoding="utf-8") as fh:
        for text, types in EXAMPLES:
            fh.write(json.dumps({"text": text, "types": sorted(types)}, ensure_ascii=False) + "\n")
    print(f"wrote {len(EXAMPLES)} examples -> {OUT}")


if __name__ == "__main__":
    main()
