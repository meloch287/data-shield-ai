"""Таксономия типов: категория данных и критичность.

Используется отчётом, фильтром `--min-severity` и пресетами (которые задаются
категориями). Неизвестный тип получает разумный дефолт.
"""
from __future__ import annotations

from typing import Dict, Iterable, Set

__all__ = [
    "CATEGORIES",
    "SEVERITY_ORDER",
    "category_of",
    "severity_of",
    "types_in_categories",
]

# категория → множество типов
_BY_CATEGORY: Dict[str, Set[str]] = {
    "contact": {"EMAIL", "PHONE", "PHONE_RU", "CHINA_MOBILE"},
    "person": {"PERSON", "ADDRESS", "POSTAL_CODE", "GEO_COORD"},
    "government_id": {
        "INN", "SNILS", "PASSPORT_RU", "DRIVER_LICENSE_RU", "OGRN", "OGRNIP",
        "KPP", "US_SSN", "US_EIN", "UK_NINO", "US_ITIN", "US_PASSPORT",
        "AADHAAR", "PAN_IN", "CHINA_ID", "CODICE_FISCALE", "FR_NIR",
        "DNI_ES", "NIE_ES", "PESEL", "DE_TAX_ID",
    },
    "financial": {"CREDIT_CARD", "IBAN", "BANK_ACCOUNT", "BIC", "ABA_ROUTING", "UK_SORT_CODE"},
    "health": {"OMS_POLICY", "NHS_UK"},
    "crypto": {"ETH_ADDRESS", "BTC_ADDRESS"},
    "network": {"IP", "MAC", "AWS_ARN"},
    "secret": {
        "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "ANTHROPIC_KEY", "OPENAI_KEY",
        "GITHUB_TOKEN", "GITLAB_TOKEN", "HF_TOKEN", "NPM_TOKEN",
        "GOOGLE_OAUTH_SECRET", "DO_TOKEN", "SHOPIFY_TOKEN", "SQUARE_TOKEN",
        "GOOGLE_API_KEY", "SLACK_TOKEN", "STRIPE_KEY", "SENDGRID_KEY",
        "TWILIO_SID", "MAILGUN_KEY", "TELEGRAM_BOT_TOKEN", "DISCORD_TOKEN",
        "SSH_PUBKEY", "JWT", "PRIVATE_KEY", "PASSWORD", "SECRET", "URL_CREDENTIALS",
    },
}

CATEGORIES = tuple(_BY_CATEGORY)

_CATEGORY_SEVERITY = {
    "contact": "medium",
    "person": "medium",
    "government_id": "high",
    "financial": "high",
    "health": "high",
    "crypto": "high",
    "network": "low",
    "secret": "critical",
}
# точечные переопределения критичности по типу
_SEVERITY_OVERRIDE = {"CREDIT_CARD": "critical"}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_TYPE_CATEGORY: Dict[str, str] = {}
for _cat, _types in _BY_CATEGORY.items():
    for _t in _types:
        _TYPE_CATEGORY[_t] = _cat


def category_of(type_name: str) -> str:
    return _TYPE_CATEGORY.get(type_name, "other")


def severity_of(type_name: str) -> str:
    if type_name in _SEVERITY_OVERRIDE:
        return _SEVERITY_OVERRIDE[type_name]
    return _CATEGORY_SEVERITY.get(category_of(type_name), "medium")


def types_in_categories(categories: Iterable[str]) -> Set[str]:
    result: Set[str] = set()
    for cat in categories:
        result |= _BY_CATEGORY.get(cat, set())
    return result
