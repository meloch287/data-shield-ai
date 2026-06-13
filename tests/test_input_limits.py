"""Тесты лимита размера ввода (max_input_size) для Data Shield AI.

Покрывает реально прочитанное поведение `datashield/engine.py`, `api.py`,
`config.py`:

  * RedactionEngine._prepare() поднимает ValueError, если len(text) превышает
    max_input_size; проверка отрабатывает и в analyze(), и в redact();
  * через публичные scan() / redact() лимит тоже срабатывает (они вызывают
    тот же движок);
  * max_input_size == 0 означает «без лимита» (любой размер проходит);
  * граница: длина ровно == лимиту разрешена, лимит+1 падает;
  * лимит конфигурируется и аргументом build_engine, и Config(max_input_size=...);
  * аргумент build_engine перекрывает значение из Config;
  * текст ошибки упоминает обе величины — фактический размер и лимит.

Все ожидания опираются на исходный код, а не на догадки. Только stdlib (unittest).

Реальное сообщение об ошибке (engine._prepare):
    f"Ввод {len(text)} символов превышает лимит {self.max_input_size}"
"""
import unittest

from datashield import Config, build_engine, redact, scan
from datashield.engine import RedactionEngine


class EngineAnalyzeLimitTests(unittest.TestCase):
    """engine.analyze() уважает max_input_size через _prepare()."""

    def test_analyze_raises_when_over_limit(self) -> None:
        engine = build_engine(max_input_size=5)
        with self.assertRaises(ValueError):
            engine.analyze("abcdef")  # len 6 > 5

    def test_analyze_at_limit_is_allowed(self) -> None:
        engine = build_engine(max_input_size=5)
        # ровно на границе — без исключения; находок нет, но это валидно
        self.assertEqual(engine.analyze("abcde"), [])

    def test_analyze_under_limit_is_allowed(self) -> None:
        engine = build_engine(max_input_size=100)
        self.assertEqual(engine.analyze("abc"), [])


class EngineRedactLimitTests(unittest.TestCase):
    """engine.redact() уважает max_input_size через _prepare()."""

    def test_redact_raises_when_over_limit(self) -> None:
        engine = build_engine(max_input_size=5)
        with self.assertRaises(ValueError):
            engine.redact("abcdef")  # len 6 > 5

    def test_redact_at_limit_is_allowed(self) -> None:
        engine = build_engine(max_input_size=5)
        result = engine.redact("abcde")
        self.assertEqual(result.masked_text, "abcde")
        self.assertEqual(result.original_length, 5)

    def test_redact_one_over_limit_fails(self) -> None:
        # граница: limit ок, limit+1 падает
        engine = build_engine(max_input_size=5)
        self.assertEqual(engine.redact("abcde").masked_text, "abcde")
        with self.assertRaises(ValueError):
            engine.redact("abcdef")


class UnlimitedZeroTests(unittest.TestCase):
    """max_input_size == 0 => без лимита (проверка в _prepare пропускается)."""

    def test_zero_means_unlimited_redact(self) -> None:
        engine = build_engine(max_input_size=0)
        big = "x" * 50000
        self.assertEqual(engine.redact(big).masked_text, big)

    def test_zero_means_unlimited_analyze(self) -> None:
        engine = build_engine(max_input_size=0)
        big = "x" * 50000
        self.assertEqual(engine.analyze(big), [])

    def test_default_engine_is_unlimited(self) -> None:
        # дефолт Config.max_input_size == 0 => лимита нет
        engine = build_engine()
        big = "y" * 20000
        self.assertEqual(engine.redact(big).masked_text, big)


class BoundaryTests(unittest.TestCase):
    """Точная граница len == limit разрешена, len == limit+1 — нет."""

    def test_exact_boundary_passes_various_limits(self) -> None:
        for limit in (1, 2, 10, 64, 256):
            engine = build_engine(max_input_size=limit)
            text = "a" * limit
            with self.subTest(limit=limit):
                self.assertEqual(engine.redact(text).masked_text, text)

    def test_one_past_boundary_fails_various_limits(self) -> None:
        for limit in (1, 2, 10, 64, 256):
            engine = build_engine(max_input_size=limit)
            text = "a" * (limit + 1)
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    engine.redact(text)

    def test_empty_text_passes_with_limit(self) -> None:
        engine = build_engine(max_input_size=1)
        self.assertEqual(engine.redact("").masked_text, "")


class PublicApiLimitTests(unittest.TestCase):
    """Лимит достижим через публичные scan() / redact() (тот же движок)."""

    def test_scan_raises_over_limit(self) -> None:
        with self.assertRaises(ValueError):
            scan("abcdef", max_input_size=5)

    def test_scan_at_limit_ok(self) -> None:
        self.assertEqual(scan("abcde", max_input_size=5), [])

    def test_redact_function_raises_over_limit(self) -> None:
        with self.assertRaises(ValueError):
            redact("abcdef", max_input_size=5)

    def test_redact_function_at_limit_ok(self) -> None:
        self.assertEqual(redact("abcde", max_input_size=5).masked_text, "abcde")


class ConfigurabilityTests(unittest.TestCase):
    """Лимит задаётся через build_engine(arg) и через Config(max_input_size=...)."""

    def test_via_build_engine_arg(self) -> None:
        engine = build_engine(max_input_size=4)
        with self.assertRaises(ValueError):
            engine.redact("abcde")  # len 5 > 4

    def test_via_config_field(self) -> None:
        engine = build_engine(Config(max_input_size=3))
        with self.assertRaises(ValueError):
            engine.redact("abcd")  # len 4 > 3

    def test_config_field_at_limit_ok(self) -> None:
        engine = build_engine(Config(max_input_size=3))
        self.assertEqual(engine.redact("abc").masked_text, "abc")

    def test_redact_function_uses_config(self) -> None:
        cfg = Config(max_input_size=3)
        with self.assertRaises(ValueError):
            redact("abcd", cfg)


class ArgOverridesConfigTests(unittest.TestCase):
    """Аргумент build_engine перекрывает Config.max_input_size.

    В api.build_engine: max_input_size=config.max_input_size if arg is None
    else arg. Значит ненулевой arg ослабляет/ужесточает лимит из конфига, а
    arg=0 (не None) перекрывает положительный конфиг на «без лимита».
    """

    def test_arg_loosens_config_limit(self) -> None:
        cfg = Config(max_input_size=3)
        engine = build_engine(cfg, max_input_size=10)
        # конфиг сказал бы «падай на len>3», но arg=10 побеждает
        self.assertEqual(engine.redact("abcdefghij").masked_text, "abcdefghij")

    def test_arg_tightens_config_limit(self) -> None:
        cfg = Config(max_input_size=100)
        engine = build_engine(cfg, max_input_size=3)
        with self.assertRaises(ValueError):
            engine.redact("abcd")  # len 4 > 3 (arg), хотя конфиг разрешал

    def test_arg_zero_overrides_config_to_unlimited(self) -> None:
        # arg=0 не None => перекрывает положительный конфиг на «без лимита»
        cfg = Config(max_input_size=3)
        engine = build_engine(cfg, max_input_size=0)
        big = "z" * 1000
        self.assertEqual(engine.redact(big).masked_text, big)

    def test_none_arg_keeps_config(self) -> None:
        # arg не передан => используется значение конфига
        cfg = Config(max_input_size=3)
        engine = build_engine(cfg)
        with self.assertRaises(ValueError):
            engine.redact("abcd")


class ErrorMessageTests(unittest.TestCase):
    """Сообщение ValueError упоминает фактический размер и лимит."""

    def test_message_mentions_both_sizes(self) -> None:
        engine = build_engine(max_input_size=5)
        with self.assertRaises(ValueError) as ctx:
            engine.redact("abcdefgh")  # len 8 > 5
        message = str(ctx.exception)
        self.assertIn("8", message)  # фактический размер
        self.assertIn("5", message)  # лимит

    def test_message_mentions_both_sizes_via_scan(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            scan("abcdefg", max_input_size=4)  # len 7 > 4
        message = str(ctx.exception)
        self.assertIn("7", message)
        self.assertIn("4", message)

    def test_message_reports_actual_input_length(self) -> None:
        # фактический размер в сообщении = len(text), а не лимит
        engine = build_engine(max_input_size=2)
        with self.assertRaises(ValueError) as ctx:
            engine.analyze("abcdef")  # len 6
        self.assertIn("6", str(ctx.exception))


class LimitCheckedBeforeNormalizationTests(unittest.TestCase):
    """Лимит проверяется по исходной длине, ДО нормализации (порядок в _prepare).

    _prepare сначала сверяет len(text) с лимитом, и только потом нормализует.
    """

    def test_limit_uses_original_length_with_normalize(self) -> None:
        text = "４１１１"  # 4 полноширинные цифры, len == 4
        self.assertEqual(len(text), 4)
        engine = build_engine(max_input_size=3, normalize=True)
        with self.assertRaises(ValueError) as ctx:
            engine.redact(text)
        # сообщение сообщает исходную длину 4, а не результат NFKC
        self.assertIn("4", str(ctx.exception))

    def test_normalize_at_exact_limit_ok(self) -> None:
        text = "４１１１"  # len 4
        engine = build_engine(max_input_size=4, normalize=True)
        # ровно на границе проходит; маска — в нормализованном пространстве
        self.assertEqual(engine.redact(text).masked_text, "4111")


class DirectEngineConstructionTests(unittest.TestCase):
    """Лимит работает и при прямой сборке RedactionEngine (без build_engine)."""

    def test_direct_engine_no_detectors_raises_over_limit(self) -> None:
        engine = RedactionEngine([], max_input_size=5)
        with self.assertRaises(ValueError):
            engine.analyze("abcdef")

    def test_direct_engine_at_limit_ok(self) -> None:
        engine = RedactionEngine([], max_input_size=5)
        self.assertEqual(engine.redact("abcde").masked_text, "abcde")


if __name__ == "__main__":
    unittest.main()
