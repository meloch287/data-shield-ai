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
            "aws_access_key", "AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            0.97, prefilter=("AKIA", "ASIA"),
        ),
        RegexDetector(
            "aws_secret", "AWS_SECRET_KEY",
            r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})",
            0.9, group=1,
        ),
        # Anthropic должен идти до OpenAI: его префикс sk-ant- уже, поэтому
        # negative lookahead в openai исключает пересечение.
        RegexDetector(
            "anthropic_key", "ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
            0.97, prefilter="sk-ant-",
        ),
        RegexDetector(
            "openai_key", "OPENAI_KEY", r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            0.95, prefilter="sk-",
        ),
        RegexDetector(
            "github_token", "GITHUB_TOKEN", r"\bgh[posru]_[A-Za-z0-9]{36,}\b",
            0.97, prefilter=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
        ),
        RegexDetector(
            "github_pat", "GITHUB_TOKEN", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b",
            0.97, prefilter="github_pat_",
        ),
        RegexDetector(
            "gitlab_token", "GITLAB_TOKEN", r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
            0.95, prefilter="glpat-",
        ),
        RegexDetector(
            "huggingface_token", "HF_TOKEN", r"\bhf_[A-Za-z0-9]{30,}\b",
            0.9, prefilter="hf_",
        ),
        RegexDetector(
            "npm_token", "NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{36}\b", 0.95, prefilter="npm_"
        ),
        RegexDetector(
            "google_oauth_secret", "GOOGLE_OAUTH_SECRET",
            r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b", 0.95, prefilter="GOCSPX-",
        ),
        RegexDetector(
            "digitalocean_token", "DO_TOKEN", r"\bdop_v1_[a-f0-9]{64}\b",
            0.95, prefilter="dop_v1_",
        ),
        RegexDetector(
            "shopify_token", "SHOPIFY_TOKEN", r"\bshpat_[a-fA-F0-9]{32}\b",
            0.95, prefilter="shpat_",
        ),
        RegexDetector(
            "square_token", "SQUARE_TOKEN", r"\bsq0atp-[A-Za-z0-9_\-]{22}\b",
            0.9, prefilter="sq0atp-",
        ),
        RegexDetector(
            "sendgrid_key", "SENDGRID_KEY",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", 0.95, prefilter="SG.",
        ),
        RegexDetector("twilio_sid", "TWILIO_SID", r"\bAC[0-9a-fA-F]{32}\b", 0.9),
        RegexDetector(
            "mailgun_key", "MAILGUN_KEY", r"\bkey-[0-9a-f]{32}\b", 0.9, prefilter="key-"
        ),
        RegexDetector(
            "telegram_bot", "TELEGRAM_BOT_TOKEN",
            r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b", 0.9,
        ),
        RegexDetector(
            "discord_token", "DISCORD_TOKEN",
            r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b", 0.85,
        ),
        RegexDetector(
            "ssh_pubkey", "SSH_PUBKEY",
            r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{40,}={0,3}",
            0.85, prefilter="ssh-",
        ),
        RegexDetector(
            "google_api_key", "GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z\-_]{35}\b",
            0.95, prefilter="AIza",
        ),
        RegexDetector(
            "slack_token", "SLACK_TOKEN", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
            0.95, prefilter="xox",
        ),
        RegexDetector(
            "stripe_key", "STRIPE_KEY", r"\b[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
            0.95, prefilter=("k_live_", "k_test_"),
        ),
        RegexDetector(
            "jwt", "JWT",
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
            0.9, prefilter="eyJ",
        ),
        RegexDetector(
            "private_key", "PRIVATE_KEY",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r"[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            0.99, prefilter="PRIVATE KEY",
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
