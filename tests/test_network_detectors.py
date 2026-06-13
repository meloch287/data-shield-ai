"""Тесты сетевых/инфраструктурных детекторов и новых детекторов секретов.

Покрывает datashield/detectors/network.py:
  * URL_CREDENTIALS — маскирует группу user:pass в scheme://user:pass@host;
    срабатывает на http/https/postgres/mongodb/redis; НЕ срабатывает без учётки;
    устойчив к ReDoS на длинном входе.
  * AWS_ARN — ловит ARN с 12-значным account id.
  * GEO_COORD — гейтится ключевым словом (lat/lon/coord/geo/location/координаты…):
    без ключевого слова уверенность 0.4 ниже порога 0.7 и через scan() ничего нет;
    с ключевым словом — 0.85 и находка проходит.

Плюс новые детекторы секретов из datashield/detectors/secrets.py:
  TWILIO_SID, MAILGUN_KEY, TELEGRAM_BOT_TOKEN, SSH_PUBKEY.

ВАЖНО про секреты: значения, похожие на реальные токены, собираются
конкатенацией строк, чтобы в исходнике не было целого литерала токена и не
сработала push-protection GitHub. Это не влияет на поведение детекторов —
детектор видит уже собранную строку.

Все ассерты проверяют ФАКТИЧЕСКОЕ наблюдаемое поведение (снято с реального кода),
а не желаемое. Где поведение интересно (overlap URL/EMAIL, гейтинг по порогу) —
есть отдельный комментарий.
"""
from __future__ import annotations

import time
import unittest

from datashield import Config, redact, scan
from datashield.detectors.network import build as build_network


def types_of(text: str, **kwargs) -> set:
    """Множество типов находок, которые реально проходят через scan()."""
    return {f.type for f in scan(text, **kwargs)}


class UrlCredentialsTests(unittest.TestCase):
    """URL_CREDENTIALS: маскирует учётную часть user:pass в URL (group 1)."""

    def test_postgres_url_credentials_detected(self):
        # Хост без точки -> нет наложения с EMAIL, URL_CREDENTIALS виден через scan.
        findings = scan("postgres://u:p@h:5432/db")
        cred = [f for f in findings if f.type == "URL_CREDENTIALS"]
        self.assertEqual(len(cred), 1)
        # group=1 -> в value только учётная часть, без схемы и хоста.
        self.assertEqual(cred[0].value, "u:p")

    def test_mongodb_url_credentials_detected(self):
        findings = scan("mongodb://me:secret@mongo:27017")
        cred = [f for f in findings if f.type == "URL_CREDENTIALS"]
        self.assertEqual(len(cred), 1)
        self.assertEqual(cred[0].value, "me:secret")

    def test_redis_url_credentials_detected(self):
        self.assertIn("URL_CREDENTIALS", types_of("redis://user:pw@cache:6379"))

    def test_redact_masks_only_user_pass_group(self):
        # Маскируется ТОЛЬКО user:pass; схема mongodb:// и хост mongo:27017 целы.
        result = redact("db at mongodb://me:secret@mongo:27017 now")
        self.assertIn("mongodb://", result.masked_text)
        self.assertIn("@mongo:27017", result.masked_text)
        self.assertNotIn("me:secret", result.masked_text)
        self.assertIn("[URL_CREDENTIALS_1]", result.masked_text)

    def test_http_url_with_dotted_host_overlaps_email(self):
        # ФАКТ: для https://user:pass@host.com учётная часть pass@host.com выглядит
        # как email, и движок при разрешении наложений отдаёт диапазон EMAIL, а не
        # URL_CREDENTIALS. Проверяем именно это наблюдаемое поведение, а не идеал.
        # Сырой детектор URL всё же находит user:pass — overlap решает движок.
        url = "https://user:pass@host.com/path"
        self.assertEqual(types_of(url), {"EMAIL"})
        url_detector = next(
            d for d in build_network() if d.type == "URL_CREDENTIALS"
        )
        raw = url_detector.detect(url)
        self.assertEqual([f.value for f in raw], ["user:pass"])

    def test_no_credentials_no_finding(self):
        # Без user:pass@ детектор молчит.
        self.assertNotIn(
            "URL_CREDENTIALS", types_of("visit https://example.com/page")
        )
        self.assertNotIn(
            "URL_CREDENTIALS", types_of("mongodb://mongo:27017/db")
        )

    def test_user_without_password_no_finding(self):
        # Нужна именно пара user:pass (двоеточие); один пользователь не считается.
        self.assertNotIn("URL_CREDENTIALS", types_of("ftp://useronly@host:21"))

    def test_redos_safe_on_long_benign_input(self):
        # ReDoS-safety: схема ограничена по длине + \b, поэтому 50КБ из 'x'
        # обрабатываются быстро и без находок. Бюджет ~0.5с с большим запасом.
        text = "x" * 50000
        start = time.perf_counter()
        findings = scan(text)
        elapsed = time.perf_counter() - start
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 0.5, f"scan занял {elapsed:.3f}s на 50КБ")

    def test_redos_safe_on_long_scheme_like_run(self):
        # Длинный ряд букв перед '://' — потенциальный триггер бэктрекинга по '*'.
        text = "a" * 50000 + "://"
        start = time.perf_counter()
        scan(text)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.5, f"scan занял {elapsed:.3f}s на scheme-входе")


class AwsArnTests(unittest.TestCase):
    """AWS_ARN: ARN содержит обязательный 12-значный account id."""

    def test_iam_user_arn_detected(self):
        self.assertIn("AWS_ARN", types_of("arn:aws:iam::123456789012:user/Bob"))

    def test_lambda_arn_detected(self):
        arn = "arn:aws:lambda:us-east-1:999988887777:function:foo"
        self.assertIn("AWS_ARN", types_of(arn))

    def test_arn_without_account_id_not_detected(self):
        # У s3-ARN account-секция пустая (arn:aws:s3:::bucket) — нет 12 цифр,
        # паттерн требует :\d{12}:, поэтому находки нет.
        self.assertNotIn("AWS_ARN", types_of("arn:aws:s3:::my-bucket/key"))

    def test_arn_value_starts_with_arn_prefix(self):
        findings = [
            f for f in scan("arn:aws:iam::123456789012:role/admin")
            if f.type == "AWS_ARN"
        ]
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].value.startswith("arn:aws"))
        self.assertIn("123456789012", findings[0].value)


class GeoCoordTests(unittest.TestCase):
    """GEO_COORD: гейтится ключевым словом через порог уверенности."""

    BARE = "55.7558, 37.6173"

    def test_bare_coordinates_not_detected_by_default(self):
        # Без ключевого слова base_confidence=0.4 < min_confidence=0.7 -> scan пуст.
        self.assertNotIn("GEO_COORD", types_of(self.BARE))

    def test_keyword_location_enables_detection(self):
        self.assertIn("GEO_COORD", types_of("location: 55.7558, 37.6173"))

    def test_keyword_russian_koordinaty_enables_detection(self):
        self.assertIn("GEO_COORD", types_of("координаты 55.7558, 37.6173"))

    def test_keyword_lat_lon_enables_detection(self):
        self.assertIn("GEO_COORD", types_of("lat/lon 55.7558, 37.6173"))

    def test_bare_coordinates_detected_with_lowered_threshold(self):
        # Подтверждаем механику гейтинга: при min_confidence=0.3 голые координаты
        # (0.4) проходят. Значит причина «тишины» по умолчанию — именно порог.
        self.assertIn("GEO_COORD", types_of(self.BARE, min_confidence=0.3))

    def test_requires_four_decimal_places(self):
        # Паттерн требует 4+ знаков после точки; 3 знака не считаются координатой.
        self.assertNotIn("GEO_COORD", types_of("location: 55.755, 37.617"))
        self.assertIn("GEO_COORD", types_of("location: 55.7558, 37.6173"))

    def test_default_min_confidence_is_above_base(self):
        # Документируем числа, на которых держится гейтинг (защита от регрессий).
        self.assertEqual(Config().min_confidence, 0.7)
        geo = next(d for d in build_network() if d.type == "GEO_COORD")
        bare = geo.detect(self.BARE)
        boosted = geo.detect("location: " + self.BARE)
        self.assertEqual(bare[0].confidence, 0.4)
        self.assertEqual(boosted[0].confidence, 0.85)


class NewSecretDetectorsTests(unittest.TestCase):
    """Новые секреты: TWILIO_SID, MAILGUN_KEY, TELEGRAM_BOT_TOKEN, SSH_PUBKEY.

    Значения собираются конкатенацией, чтобы целый литерал токена не попал в
    исходник (push-protection). 32-символьные hex-хвосты строятся повтором.
    """

    HEX32 = "0123456789abcdef" * 2  # 32 hex-символа

    def test_twilio_sid_detected(self):
        # AC + 32 hex.
        twilio = "AC" + self.HEX32
        self.assertEqual(len(twilio) - 2, 32)
        self.assertIn("TWILIO_SID", types_of(twilio))

    def test_twilio_sid_uppercase_hex(self):
        # Паттерн [0-9a-fA-F] -> верхний регистр hex тоже валиден.
        twilio = "AC" + ("0123456789ABCDEF" * 2)
        self.assertIn("TWILIO_SID", types_of(twilio))

    def test_mailgun_key_detected(self):
        # key- + 32 hex (нижний регистр).
        mailgun = "key" + "-" + self.HEX32
        self.assertIn("MAILGUN_KEY", types_of(mailgun))

    def test_mailgun_key_redacts_to_placeholder(self):
        mailgun = "key" + "-" + self.HEX32
        result = redact("token is " + mailgun)
        self.assertIn("[MAILGUN_KEY_1]", result.masked_text)
        self.assertNotIn(mailgun, result.masked_text)

    def test_telegram_bot_token_detected(self):
        # 8-10 цифр ':' 35 символов. Суффикс собираем из кусков.
        suffix = ("A" * 10) + ("b" * 10) + ("C" * 10) + "12345"
        self.assertEqual(len(suffix), 35)
        token = "12345678" + ":" + suffix
        self.assertIn("TELEGRAM_BOT_TOKEN", types_of(token))

    def test_telegram_bot_token_requires_min_eight_digits(self):
        # 7 цифр перед двоеточием -> не телеграм-токен.
        suffix = ("A" * 10) + ("b" * 10) + ("C" * 10) + "12345"
        seven = "1234567" + ":" + suffix
        eight = "12345678" + ":" + suffix
        self.assertNotIn("TELEGRAM_BOT_TOKEN", types_of(seven))
        self.assertIn("TELEGRAM_BOT_TOKEN", types_of(eight))

    def test_ssh_pubkey_rsa_detected(self):
        # ssh-rsa <base64 40+ символов>.
        key = "ssh" + "-" + "rsa" + " " + ("A" * 60) + "=="
        self.assertIn("SSH_PUBKEY", types_of(key))

    def test_ssh_pubkey_ed25519_detected(self):
        key = "ssh" + "-" + "ed25519" + " " + ("B" * 50)
        self.assertIn("SSH_PUBKEY", types_of(key))

    def test_ssh_pubkey_unknown_algo_not_detected(self):
        # Паттерн допускает только rsa/ed25519/dss; прочие алгоритмы не ловятся.
        key = "ssh" + "-" + "foobar" + " " + ("A" * 60)
        self.assertNotIn("SSH_PUBKEY", types_of(key))


class CatalogShapeTests(unittest.TestCase):
    """Каталог детекторов: фиксируем заявленные числа (защита от регрессий)."""

    def test_catalog_counts_match_block_c(self):
        from datashield.detectors.registry import build_active, build_catalog

        catalog = build_catalog(Config())
        self.assertEqual(len(catalog), 75)
        self.assertEqual(sum(1 for i in catalog if i.default_enabled), 71)
        self.assertEqual(len(build_active(Config())), 71)
        self.assertEqual(len({i.detector.type for i in catalog}), 68)


if __name__ == "__main__":
    unittest.main()
