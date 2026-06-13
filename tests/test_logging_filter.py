"""Тесты RedactingFilter — маскировки конфиденциальных данных в логах.

Проверяем реальное поведение datashield.integrations.logging_filter.RedactingFilter:
итоговое сообщение (с подставленными %-аргументами) маскируется на месте,
record.args очищается, сообщения без ПДн проходят без изменений, фильтр всегда
возвращает True (включая случай, когда getMessage() падает), кастомный движок
внедряется через конструктор.
"""
import io
import logging
import unittest

from datashield.engine import RedactionResult
from datashield.integrations.logging_filter import RedactingFilter


def _make_record(msg, args=()):
    return logging.LogRecord(
        name="test", level=logging.INFO, pathname="p", lineno=1,
        msg=msg, args=args, exc_info=None,
    )


class _RecordingEngine:
    """Минимальный движок-двойник: фиксирует вход, возвращает заданный результат."""

    def __init__(self, masked_text):
        self.masked_text = masked_text
        self.calls = []

    def redact(self, text):
        self.calls.append(text)
        return RedactionResult(
            original_length=len(text),
            masked_text=self.masked_text,
            findings=[],
            stats={},
            placeholders={},
        )


class LoggerIntegrationTests(unittest.TestCase):
    """Фильтр, подключённый к настоящему логгеру со StringIO-обработчиком."""

    def setUp(self):
        self.stream = io.StringIO()
        handler = logging.StreamHandler(self.stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger = logging.getLogger("datashield.test.logging_filter")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = [handler]
        self.logger.propagate = False
        self.filter = RedactingFilter()
        self.logger.addFilter(self.filter)

    def tearDown(self):
        self.logger.removeFilter(self.filter)
        self.logger.handlers = []

    def _output(self):
        return self.stream.getvalue()

    def test_email_in_args_is_masked_in_output(self):
        self.logger.info("email %s", "a@b.com")
        self.assertEqual(self._output(), "email [EMAIL_1]\n")
        self.assertNotIn("a@b.com", self._output())

    def test_plain_message_passes_through_unchanged(self):
        self.logger.info("hello %s", "world")
        self.assertEqual(self._output(), "hello world\n")

    def test_multiple_pii_in_one_record(self):
        self.logger.info("from %s to %s", "a@b.com", "c@d.com")
        out = self._output()
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[EMAIL_2]", out)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("c@d.com", out)


class FilterMethodTests(unittest.TestCase):
    """Прямой вызов filter() на сконструированных LogRecord."""

    def setUp(self):
        self.filter = RedactingFilter()

    def test_returns_true_when_masking_happens(self):
        record = _make_record("email %s", ("a@b.com",))
        self.assertTrue(self.filter.filter(record))

    def test_returns_true_when_nothing_masked(self):
        record = _make_record("count %d", (5,))
        self.assertTrue(self.filter.filter(record))

    def test_args_cleared_after_masking(self):
        record = _make_record("email %s", ("a@b.com",))
        self.filter.filter(record)
        self.assertEqual(record.msg, "email [EMAIL_1]")
        # После маскировки args очищается, чтобы повторный getMessage не падал.
        self.assertEqual(record.args, ())
        self.assertEqual(record.getMessage(), "email [EMAIL_1]")

    def test_msg_and_args_preserved_when_no_pii(self):
        record = _make_record("count %d", (5,))
        self.filter.filter(record)
        # Без ПДн msg/args не трогаются — форматирование остаётся ленивым.
        self.assertEqual(record.msg, "count %d")
        self.assertEqual(record.args, (5,))
        self.assertEqual(record.getMessage(), "count 5")

    def test_multiple_pii_in_single_record(self):
        record = _make_record("a@b.com and c@d.com", ())
        self.filter.filter(record)
        self.assertIn("[EMAIL_1]", record.msg)
        self.assertIn("[EMAIL_2]", record.msg)
        self.assertNotIn("a@b.com", record.msg)
        self.assertNotIn("c@d.com", record.msg)

    def test_record_whose_getmessage_raises_does_not_crash(self):
        # '%d' с нечисловым аргументом → getMessage() бросает TypeError.
        record = _make_record("bad %d", ("not-a-number",))
        # Не должно бросить, должно вернуть True, и движок не вызывается.
        result = self.filter.filter(record)
        self.assertTrue(result)


class CustomEngineInjectionTests(unittest.TestCase):
    """Внедрение собственного движка через конструктор."""

    def test_injected_engine_is_used(self):
        engine = _RecordingEngine(masked_text="REDACTED")
        flt = RedactingFilter(engine=engine)
        self.assertIs(flt.engine, engine)

    def test_injected_engine_receives_full_message(self):
        engine = _RecordingEngine(masked_text="REDACTED")
        flt = RedactingFilter(engine=engine)
        record = _make_record("token %s", ("secret",))
        flt.filter(record)
        # Движку передаётся уже отформатированное сообщение, не сырой шаблон.
        self.assertEqual(engine.calls, ["token secret"])
        self.assertEqual(record.msg, "REDACTED")
        self.assertEqual(record.args, ())

    def test_injected_engine_returning_unchanged_keeps_record(self):
        # Если движок не меняет текст — msg/args остаются нетронутыми.
        engine = _RecordingEngine(masked_text="hello world")
        flt = RedactingFilter(engine=engine)
        record = _make_record("hello %s", ("world",))
        result = flt.filter(record)
        self.assertTrue(result)
        self.assertEqual(record.msg, "hello %s")
        self.assertEqual(record.args, ("world",))

    def test_default_engine_built_when_none(self):
        flt = RedactingFilter()
        self.assertIsNotNone(flt.engine)
        self.assertTrue(hasattr(flt.engine, "redact"))


class FilterConstructionTests(unittest.TestCase):
    """RedactingFilter — это logging.Filter и совместим с механизмом name-фильтра."""

    def test_is_logging_filter_subclass(self):
        self.assertIsInstance(RedactingFilter(), logging.Filter)

    def test_name_argument_forwarded_to_base(self):
        flt = RedactingFilter(name="datashield")
        # logging.Filter сохраняет имя в .name.
        self.assertEqual(flt.name, "datashield")


if __name__ == "__main__":
    unittest.main()
