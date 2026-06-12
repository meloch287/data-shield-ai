"""Детекторы секретов: API-ключи, токены, приватные ключи, пароли.

У большинства провайдеров ключи имеют отличимый префикс (AKIA, sk-ant-, ghp_),
что даёт высокую точность. Присваивания `password=…` маскируют только значение.
high_entropy ловит неизвестные ключи, но выключен по умолчанию ради
предсказуемости (включается в конфиге).
"""
from __future__ import annotations

import re
from typing import List

from datashield.detectors.base import Finding, RegexDetector
from datashield.validators import shannon_entropy

__all__ = ["build", "build_optional", "HighEntropyDetector"]


def build() -> List[RegexDetector]:
    return [
        RegexDetector(
            "aws_access_key",
            "AWS_ACCESS_KEY",
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            0.97,
        ),
        RegexDetector(
            "aws_secret",
            "AWS_SECRET_KEY",
            r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})",
            0.9,
            group=1,
        ),
        # Anthropic должен идти до OpenAI: его префикс sk-ant- уже, поэтому
        # negative lookahead в openai исключает пересечение.
        RegexDetector(
            "anthropic_key",
            "ANTHROPIC_KEY",
            r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
            0.97,
        ),
        RegexDetector(
            "openai_key",
            "OPENAI_KEY",
            r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            0.95,
        ),
        RegexDetector(
            "github_token",
            "GITHUB_TOKEN",
            r"\bgh[posru]_[A-Za-z0-9]{36,}\b",
            0.97,
        ),
        RegexDetector(
            "google_api_key",
            "GOOGLE_API_KEY",
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            0.95,
        ),
        RegexDetector(
            "slack_token",
            "SLACK_TOKEN",
            r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
            0.95,
        ),
        RegexDetector(
            "stripe_key",
            "STRIPE_KEY",
            r"\b[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
            0.95,
        ),
        RegexDetector(
            "jwt",
            "JWT",
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
            0.9,
        ),
        RegexDetector(
            "private_key",
            "PRIVATE_KEY",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r"[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            0.99,
        ),
        # Пароль в присваивании — маскируется только значение (group 1).
        RegexDetector(
            "password",
            "PASSWORD",
            r"(?i)(?:password|passwd|pwd|пароль)\s*[=:]\s*['\"]?([^\s'\"]{4,})",
            0.85,
            group=1,
        ),
        # Обобщённое присваивание секрета/токена.
        RegexDetector(
            "secret_assignment",
            "SECRET",
            r"(?i)(?:secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)"
            r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-./+]{8,})",
            0.8,
            group=1,
        ),
    ]


class HighEntropyDetector:
    """Ловит длинные строки с высокой энтропией — потенциальные ключи.

    Выключен по умолчанию: склонен к ложным срабатываниям на хешах/UUID.
    Включается через config (`enabled_detectors`).
    """

    name = "high_entropy"
    type = "SECRET"

    def __init__(
        self,
        min_length: int = 20,
        min_entropy: float = 4.0,
        confidence: float = 0.75,
    ) -> None:
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.confidence = confidence
        self._regex = re.compile(r"[A-Za-z0-9+/_\-=]{%d,}" % min_length)

    def detect(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for match in self._regex.finditer(text):
            value = match.group()
            if shannon_entropy(value) >= self.min_entropy:
                findings.append(
                    Finding(
                        self.type,
                        match.start(),
                        match.end(),
                        value,
                        self.confidence,
                        self.name,
                    )
                )
        return findings


def build_optional() -> List[HighEntropyDetector]:
    return [HighEntropyDetector()]
