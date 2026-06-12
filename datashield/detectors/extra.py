"""Дополнительные идентификаторы: РФ-реквизиты и международные ID.

РФ: ОГРН/ОГРНИП (контрольная цифра), КПП, БИК, расчётный счёт, полис ОМС,
водительское удостоверение. Многие — короткие цифровые последовательности,
поэтому контекстно-зависимые (нужно ключевое слово рядом).
Международные: US SSN/EIN, UK NINO, крипто-кошельки ETH/BTC.
"""
from __future__ import annotations

from typing import List

from datashield.detectors.base import KeywordContextDetector, RegexDetector
from datashield.validators import validate_ogrn, validate_ogrnip

__all__ = ["build"]


def build() -> List[object]:
    return [
        RegexDetector(
            "ogrn", "OGRN", r"(?<!\d)\d{13}(?!\d)", 0.85, validator=validate_ogrn
        ),
        RegexDetector(
            "ogrnip", "OGRNIP", r"(?<!\d)\d{15}(?!\d)", 0.85, validator=validate_ogrnip
        ),
        KeywordContextDetector(
            "kpp", "KPP", r"(?<!\w)\d{4}[0-9A-Z]{2}\d{3}(?!\w)",
            0.4, 0.9, r"\bКПП\b",
        ),
        KeywordContextDetector(
            "bic", "BIC", r"(?<!\d)04\d{7}(?!\d)", 0.55, 0.92, r"\bБИК\b",
        ),
        KeywordContextDetector(
            "bank_account", "BANK_ACCOUNT", r"(?<!\d)\d{20}(?!\d)",
            0.55, 0.9, r"счёт|счет|р/с|расч[ёе]тн",
        ),
        KeywordContextDetector(
            "oms_policy", "OMS_POLICY", r"(?<!\d)\d{16}(?!\d)",
            0.4, 0.92, r"полис|ОМС",
        ),
        KeywordContextDetector(
            "driver_license_ru", "DRIVER_LICENSE_RU",
            r"(?<!\d)\d{2}\s?\d{2}\s?\d{6}(?!\d)",
            0.4, 0.9, r"водительск|удостоверен|\bВУ\b|права",
        ),
        # SSN/NINO форматы совпадают с артикулами/тикетами, поэтому требуют
        # ключевого слова рядом (иначе слишком много ложных срабатываний).
        KeywordContextDetector(
            "us_ssn", "US_SSN", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
            0.5, 0.92, r"\bSSN\b|social\s+security|\bsocial\b",
        ),
        KeywordContextDetector(
            "us_ein", "US_EIN", r"(?<!\d)\d{2}-\d{7}(?!\d)", 0.4, 0.9, r"\bEIN\b",
        ),
        KeywordContextDetector(
            "uk_nino", "UK_NINO", r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
            0.5, 0.92, r"\bNINO\b|national\s+insurance|\bNI\s+number",
        ),
        RegexDetector("eth_address", "ETH_ADDRESS", r"\b0x[a-fA-F0-9]{40}\b", 0.95),
        RegexDetector(
            "btc_address", "BTC_ADDRESS",
            r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", 0.78,
        ),
    ]
