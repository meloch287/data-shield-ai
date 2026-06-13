"""Паритет пре-фильтра + санити по перфу (Block I).

RegexDetector принимает prefilter=str|tuple — дешёвый литеральный пре-скрин:
если ни одного литерала нет в тексте, detect() возвращает [] без запуска
дорогого finditer. Каждый литерал гарантированно присутствует в любом матче
своего паттерна, поэтому пре-фильтр НЕ должен ронять ни одной находки.

Этот модуль:
  * собирает ~25 разнородных входов (чистая проза, код, логи, и входы с каждым
    типом секрета, собранным конкатенацией — чтобы тело файла не содержало
    «живых» ключей);
  * для КАЖДОГО проверяет, что множество найденных типов — ожидаемое;
  * перекрёстно подтверждает, что пре-фильтрация ничего не теряет: каждый
    RegexDetector с пре-фильтром даёт идентичные находки и со включённым, и с
    выключенным пре-фильтром (twin-копия с очищенным _prefilter);
  * лёгкая проверка перфа: редакция 50 КБ ЧИСТОГО текста (без секретов, без '@')
    укладывается в < 0.2с — пре-фильтр пропускает ~20 secret-регэкспов.

Запуск:
    cd /Users/meloch287/Desktop/data-shield-ai && \
        python3 -m unittest tests.test_prefilter_parity -v
"""
from __future__ import annotations

import copy
import io
import os
import tempfile
import time
import unittest

from datashield.api import build_engine
from datashield.batch import redact_files
from datashield.config import Config
from datashield.detectors.base import RegexDetector
from datashield.detectors.registry import build_active
from datashield.streaming import redact_stream

# Секретные значения строим конкатенацией, чтобы файл не содержал «живых»
# ключей и не триггерил сканеры секретов на самом тесте.
AT = "@"
SK = "sk-"


def _types(engine, text):
    """Множество типов находок, отсортированное для детерминизма сравнения."""
    return sorted({f.type for f in engine.analyze(text)})


# (метка, текст, ожидаемое множество типов).
# Поведение каждого пункта подтверждено прямым прогоном реального движка.
def _cases():
    aws = "AKIA" + "ABCDEFGHIJ123456"
    asia = "ASIA" + "ABCDEFGHIJ123456"
    anthropic = SK + "ant-" + "api03-" + "A" * 40
    openai = SK + "proj-" + "B" * 40
    github = "ghp_" + "a" * 36
    github_pat = "github_pat_" + "A" * 60
    gitlab = "glpat-" + "x" * 20
    hf = "hf_" + "Q" * 30
    npm = "npm_" + "z" * 36
    do = "dop_v1_" + "a" * 64
    google_api = "AIza" + "C" * 35
    slack = "xoxb-" + "1234567890" + "-abcdefghij"
    stripe = "sk_live_" + "A" * 24
    jwt = "eyJ" + "abc123" + ".eyJ" + "def456" + "." + "ghi789xyz"
    eth = "0x" + "a" * 40
    pkey = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "MIIBOgIBAAJBAK" + "x" * 48
        + "\n-----END RSA PRIVATE KEY-----"
    )

    return [
        # --- Чистые входы: типов быть не должно. ---
        ("clean_prose",
         "The quick brown fox jumps over the lazy dog. "
         "Plain prose, nothing to redact at all.", []),
        ("clean_prose_2",
         "Meeting notes: discuss roadmap, assign owners, set deadlines. "
         "No sensitive data here.", []),
        ("code_python",
         "def add(a, b):\n    return a + b\n\nprint(add(1, 2))", []),
        ("code_json",
         '{"name": "widget", "count": 42, "enabled": true}', []),
        ("log_clean",
         "2026-06-13 10:00:00 INFO Starting service "
         "version 1.2.3.4 build 567", []),
        ("log_clean_2",
         "WARN cache miss for key=user-profile latency=12ms retries=3", []),
        ("version_number_not_ip",
         "running version 1.2.3.4 now, please upgrade", []),

        # --- По одному секрету на вход. ---
        ("email",
         "reach me at user" + AT + "example.com when ready", ["EMAIL"]),
        ("aws_akia", "key " + aws + " rotated", ["AWS_ACCESS_KEY"]),
        ("aws_asia", "temp creds " + asia, ["AWS_ACCESS_KEY"]),
        ("anthropic", "export KEY=" + anthropic, ["ANTHROPIC_KEY"]),
        ("openai", "export KEY=" + openai, ["OPENAI_KEY"]),
        ("github", "token " + github, ["GITHUB_TOKEN"]),
        ("github_pat", "token " + github_pat, ["GITHUB_TOKEN"]),
        ("gitlab", "GITLAB_TOKEN=" + gitlab, ["GITLAB_TOKEN"]),
        ("huggingface", "HF=" + hf, ["HF_TOKEN"]),
        ("npm", "//registry/:_authToken=" + npm, ["NPM_TOKEN"]),
        ("digitalocean", "DO=" + do, ["DO_TOKEN"]),
        ("google_api", "GOOGLE_KEY=" + google_api, ["GOOGLE_API_KEY"]),
        ("slack", "SLACK=" + slack, ["SLACK_TOKEN"]),
        ("stripe", "STRIPE_KEY=" + stripe, ["STRIPE_KEY"]),
        ("jwt", "Authorization: Bearer " + jwt, ["JWT"]),
        ("eth", "wallet " + eth, ["ETH_ADDRESS"]),
        ("private_key", "config:\n" + pkey, ["PRIVATE_KEY"]),
        ("ipv4", "host 10.0.0.1 reachable", ["IP"]),
        ("mac", "iface mac 00:1A:2B:3C:4D:5E up", ["MAC"]),
        ("credit_card", "paid with 4111 1111 1111 1111 today", ["CREDIT_CARD"]),
        ("iban", "transfer to GB82 WEST 1234 5698 7654 32", ["IBAN"]),
        ("phone", "call me at +1 415 555 2671 tonight", ["PHONE"]),
        ("password", "password: supersecret123", ["PASSWORD"]),
        ("url_credentials",
         "dsn postgres://admin:secretpw" + AT + "host/db",
         ["URL_CREDENTIALS"]),

        # --- Смешанные входы: несколько типов в одном тексте. ---
        ("mixed_email_aws",
         "user" + AT + "corp.com logged in with key " + aws,
         ["AWS_ACCESS_KEY", "EMAIL"]),
        ("mixed_openai_github",
         "OPENAI_API_KEY=" + openai + "\nGITHUB_TOKEN=" + github,
         ["GITHUB_TOKEN", "OPENAI_KEY"]),
        ("mixed_anthropic_jwt",
         "key " + anthropic + " and token " + jwt,
         ["ANTHROPIC_KEY", "JWT"]),
        ("mixed_log_ip_email",
         "2026-06-13 ERROR client 10.0.0.1 user "
         + "ops" + AT + "svc.io failed auth",
         ["EMAIL", "IP"]),
    ]


class PrefilterParityTest(unittest.TestCase):
    """Для каждого входа: ожидаемые типы + пре-фильтр ничего не теряет."""

    @classmethod
    def setUpClass(cls):
        # Дефолтный движок (как build_engine() в streaming/api по умолчанию).
        cls.engine = build_engine()
        cls.cases = _cases()
        # RegexDetector'ы с непустым пре-фильтром — на них проверяем паритет.
        cls.prefiltered = [
            d
            for d in build_active(Config())
            if isinstance(d, RegexDetector) and d._prefilter
        ]

    def test_have_prefiltered_detectors(self):
        # Санити: пре-фильтр действительно используется на множестве детекторов.
        self.assertGreaterEqual(
            len(self.prefiltered),
            15,
            "ожидали много детекторов с пре-фильтром (email, aws, "
            "anthropic, openai, github, jwt, private_key, eth, ...)",
        )
        types = {d.type for d in self.prefiltered}
        for expected in {"EMAIL", "AWS_ACCESS_KEY", "ANTHROPIC_KEY",
                         "OPENAI_KEY", "JWT", "PRIVATE_KEY", "ETH_ADDRESS"}:
            self.assertIn(expected, types)

    def test_at_least_25_cases(self):
        self.assertGreaterEqual(len(self.cases), 25)

    def test_expected_types_per_input(self):
        # Каждый вход даёт ровно ожидаемое множество типов.
        for label, text, expected in self.cases:
            with self.subTest(case=label):
                self.assertEqual(_types(self.engine, text), expected)

    def test_clean_inputs_yield_nothing(self):
        # Чистая проза/код/логи не должны давать НИ ОДНОЙ находки.
        for label, text, expected in self.cases:
            if expected:
                continue
            with self.subTest(case=label):
                self.assertEqual(self.engine.analyze(text), [])

    def test_prefilter_drops_nothing(self):
        """Ключевой паритет: для каждого входа и каждого пре-фильтрованного
        детектора результат detect() идентичен со включённым и выключенным
        пре-фильтром. Если пре-фильтр когда-либо ронял бы валидную находку,
        twin (без пре-фильтра) нашёл бы её, а оригинал — нет."""
        for label, text, _expected in self.cases:
            for det in self.prefiltered:
                with_pf = det.detect(text)
                twin = copy.copy(det)
                twin._prefilter = ()  # отключаем пре-фильтр на копии
                without_pf = twin.detect(text)
                with self.subTest(case=label, detector=det.name):
                    self.assertEqual(
                        [(f.type, f.start, f.end, f.value) for f in with_pf],
                        [(f.type, f.start, f.end, f.value) for f in without_pf],
                        f"пре-фильтр изменил находки {det.name} на {label!r}",
                    )

    def test_prefilter_skips_when_literal_absent(self):
        # Прямое подтверждение короткого замыкания: паттерн совпал бы, но
        # литерала пре-фильтра нет -> detect() == [] (дорогой regex пропущен).
        det = RegexDetector("probe", "PROBE", r"\d{3}", 0.9, prefilter="ZZZ")
        self.assertEqual(det.detect("123 456 789"), [])
        twin = copy.copy(det)
        twin._prefilter = ()
        self.assertEqual([f.value for f in twin.detect("123 456 789")],
                         ["123", "456", "789"])

    def test_present_secrets_found_absent_not(self):
        """Кросс-проверка построением движка: секрет, присутствующий во входе,
        находится; отсутствующий — нет."""
        anthropic = SK + "ant-" + "api03-" + "A" * 40
        with_secret = "config key=" + anthropic
        without_secret = "config key=placeholder_value_here"
        self.assertIn("ANTHROPIC_KEY", _types(self.engine, with_secret))
        self.assertEqual(_types(self.engine, without_secret), [])


class PrefilterPerfTest(unittest.TestCase):
    """Лёгкая проверка перфа: чистый 50 КБ текст редактируется быстро."""

    def test_clean_50kb_is_fast(self):
        # ~54 КБ чистого текста: ни секретов, ни '@'. Пре-фильтр должен
        # пропустить ~20 secret-регэкспов и email, поэтому быстро.
        engine = build_engine()
        clean = "The quick brown fox jumps over the lazy dog. " * 1200
        self.assertGreaterEqual(len(clean), 50_000)
        self.assertNotIn(AT, clean)
        # Прогрев импорта/компиляции регэкспов вне измерения.
        engine.redact("warmup text without secrets")
        start = time.perf_counter()
        result = engine.redact(clean)
        elapsed = time.perf_counter() - start
        self.assertEqual(result.findings, [])
        self.assertLess(
            elapsed,
            0.2,
            f"чистый 50КБ текст редактировался {elapsed:.3f}s (ожидали < 0.2s)",
        )


class StreamingParityTest(unittest.TestCase):
    """Потоковая редакция: число находок и текст совпадают с прямым движком."""

    def test_stream_counts_findings(self):
        engine = build_engine()
        body = (
            "line one is clean\n"
            "email me at a" + AT + "b.com\n"
            "another clean line\n"
        )
        src = io.StringIO(body)
        out = io.StringIO()
        count = redact_stream(src, out, engine, block_lines=2)
        self.assertEqual(count, 1)
        self.assertIn("[EMAIL_1]", out.getvalue())
        self.assertNotIn(AT + "b.com", out.getvalue())

    def test_stream_clean_block_no_findings(self):
        engine = build_engine()
        src = io.StringIO("clean one\nclean two\nclean three\n")
        out = io.StringIO()
        count = redact_stream(src, out, engine, block_lines=2)
        self.assertEqual(count, 0)
        self.assertEqual(out.getvalue(), "clean one\nclean two\nclean three\n")


class BatchParityTest(unittest.TestCase):
    """Пакетная редакция через ProcessPool: малые worker'ы, top-level файлы."""

    def test_batch_serial_and_parallel_agree(self):
        with tempfile.TemporaryDirectory() as d:
            in1 = os.path.join(d, "a.txt")
            in2 = os.path.join(d, "b.txt")
            with open(in1, "w", encoding="utf-8") as fh:
                fh.write("contact a" + AT + "b.com please\n")
            with open(in2, "w", encoding="utf-8") as fh:
                fh.write("nothing sensitive in this file\n")

            out_serial1 = os.path.join(d, "a.s.out")
            out_serial2 = os.path.join(d, "b.s.out")
            serial = redact_files(
                [(in1, out_serial1), (in2, out_serial2)], workers=1
            )
            self.assertEqual(serial[out_serial1], 1)
            self.assertEqual(serial[out_serial2], 0)

            out_par1 = os.path.join(d, "a.p.out")
            out_par2 = os.path.join(d, "b.p.out")
            parallel = redact_files(
                [(in1, out_par1), (in2, out_par2)], workers=2
            )
            self.assertEqual(parallel[out_par1], 1)
            self.assertEqual(parallel[out_par2], 0)

            with open(out_par1, encoding="utf-8") as fh:
                masked = fh.read()
            self.assertIn("[EMAIL_1]", masked)
            self.assertNotIn(AT + "b.com", masked)

    def test_batch_single_file_serial(self):
        # Один файл -> serial-путь (без ProcessPool).
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "only.txt")
            outp = os.path.join(d, "only.out")
            with open(inp, "w", encoding="utf-8") as fh:
                fh.write("key AKIA" + "ABCDEFGHIJ123456" + " leaked\n")
            res = redact_files([(inp, outp)], workers=4)
            self.assertEqual(res[outp], 1)


if __name__ == "__main__":
    unittest.main()
