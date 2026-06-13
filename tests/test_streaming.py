"""Тесты потоковой редакции (datashield.streaming) и батча (datashield.batch).

Проверяем РЕАЛЬНОЕ поведение, наблюдённое на источниках:

  * redact_stream маскирует каждую строку с email/ИНН, не утекая сырое значение,
    и возвращает корректное число находок;
  * запись идёт инкрементально — по одному write() на блок;
  * block_lines управляет батчингом; при ОДИНАКОВЫХ значениях во всех строках
    вывод побайтово идентичен при block_lines = 1, 10 и по умолчанию (нумерация
    плейсхолдеров стабильна), а число находок не зависит от block_lines;
  * redact_file (через временные файлы): in -> out; пустой ввод -> пустой вывод,
    count 0; одна строка;
  * многострочная находка (блок PRIVATE KEY) ЦЕЛИКОМ внутри одного блока находится;
  * находка, разорванная ровно по границе блока, — задокументированное ограничение
    (не находится, тело утекает).

ИНН требует ключевого слова «ИНН» рядом, иначе уверенность ниже порога 0.7 —
поэтому в тестах ИНН всегда даётся с ключевым словом.
"""
import io
import os
import tempfile
import unittest

from datashield import build_engine
from datashield.batch import redact_files, redact_one
from datashield.streaming import redact_file, redact_stream

# Строим секреты конкатенацией, чтобы сырые значения не лежали в исходнике as-is.
_EMAIL = "user" + "@" + "example" + ".com"
_INN = "7707" + "083" + "893"  # валидный 10-значный ИНН (как в источниках)
_INN_KW = "ИНН"


def _line(i: int) -> str:
    """Строка с УНИКАЛЬНЫМ email и общим ИНН (ИНН переиспользует плейсхолдер)."""
    return "row{0} email user{0}".format(i) + "@" + "ex.com " + _INN_KW + " " + _INN + "\n"


def _same_line() -> str:
    """Строка с ОДИНАКОВЫМИ значениями (стабильная нумерация плейсхолдеров)."""
    return "contact " + _EMAIL + " " + _INN_KW + " " + _INN + "\n"


class _CountingWriter:
    """Накопитель записей: считает число вызовов write() (инкрементальность)."""

    def __init__(self) -> None:
        self.writes = 0
        self._chunks = []

    def write(self, s: str) -> int:
        self.writes += 1
        self._chunks.append(s)
        return len(s)

    def getvalue(self) -> str:
        return "".join(self._chunks)


class RedactStreamBasicTests(unittest.TestCase):
    def test_masks_every_line_no_raw_leak_and_counts(self):
        n = 25
        text = "".join(_line(i) for i in range(n))
        out = io.StringIO()
        count = redact_stream(io.StringIO(text), out, build_engine(), block_lines=2000)
        result = out.getvalue()

        # Каждая строка замаскирована: на каждую приходится EMAIL + INN.
        self.assertEqual(count, 2 * n)
        # Ни одно сырое значение не утекло.
        self.assertNotIn(_EMAIL.split("@")[1], result.replace("ex.com", ""))
        self.assertNotIn(_INN, result)
        for i in range(n):
            self.assertNotIn("user{0}@ex.com".format(i), result)
        # Плейсхолдеры присутствуют на каждой строке.
        self.assertEqual(result.count("[EMAIL_"), n)
        self.assertEqual(result.count("[INN_"), n)
        # Ключевое слово «ИНН» (контекст, не сам секрет) сохраняется.
        self.assertEqual(result.count(_INN_KW), n)

    def test_single_line_without_trailing_newline(self):
        out = io.StringIO()
        count = redact_stream(
            io.StringIO("only one line email " + _EMAIL),
            out,
            build_engine(),
            block_lines=2000,
        )
        self.assertEqual(count, 1)
        self.assertEqual(out.getvalue(), "only one line email [EMAIL_1]")
        self.assertNotIn(_EMAIL, out.getvalue())

    def test_empty_input_yields_empty_output_and_zero_count(self):
        out = io.StringIO()
        count = redact_stream(io.StringIO(""), out, build_engine(), block_lines=10)
        self.assertEqual(count, 0)
        self.assertEqual(out.getvalue(), "")

    def test_block_with_no_sensitive_data_preserved_verbatim(self):
        plain = "just some plain words\nno secrets here at all\n"
        out = io.StringIO()
        count = redact_stream(io.StringIO(plain), out, build_engine(), block_lines=1)
        self.assertEqual(count, 0)
        self.assertEqual(out.getvalue(), plain)


class IncrementalWriteTests(unittest.TestCase):
    def test_writes_one_chunk_per_block(self):
        # 6 строк, block_lines=2 -> 3 блока -> ровно 3 вызова write().
        text = "".join(_line(i) for i in range(6))
        writer = _CountingWriter()
        count = redact_stream(io.StringIO(text), writer, build_engine(), block_lines=2)
        self.assertEqual(writer.writes, 3)
        self.assertEqual(count, 12)
        self.assertNotIn(_INN, writer.getvalue())

    def test_default_block_lines_writes_once_for_small_input(self):
        # При block_lines по умолчанию (2000) малый вход уходит одним финальным write.
        text = "".join(_line(i) for i in range(5))
        writer = _CountingWriter()
        redact_stream(io.StringIO(text), writer, build_engine())  # block_lines=2000
        self.assertEqual(writer.writes, 1)


class BlockLinesBatchingTests(unittest.TestCase):
    """block_lines меняет батчинг, но число находок постоянно; при одинаковых
    значениях во всех строках вывод побайтово одинаков."""

    def _run(self, block_lines: int, line_text: str, rows: int):
        text = line_text * rows
        out = io.StringIO()
        # Свежий движок на каждый прогон — изоляция нумерации плейсхолдеров.
        count = redact_stream(
            io.StringIO(text), out, build_engine(), block_lines=block_lines
        )
        return count, out.getvalue()

    def test_count_independent_of_block_lines(self):
        rows = 12
        line = _line(0)  # одинаковая строка целиком -> детектируемо одинаково
        c1, _ = self._run(1, line, rows)
        c10, _ = self._run(10, line, rows)
        cdef, _ = self._run(2000, line, rows)
        self.assertEqual(c1, 2 * rows)
        self.assertEqual(c1, c10)
        self.assertEqual(c1, cdef)

    def test_identical_output_for_identical_per_line_values(self):
        rows = 6
        line = _same_line()
        c1, o1 = self._run(1, line, rows)
        c10, o10 = self._run(10, line, rows)
        cdef, odef = self._run(2000, line, rows)
        # Нумерация плейсхолдеров стабильна (значения совпадают) -> вывод идентичен.
        self.assertEqual(o1, o10)
        self.assertEqual(o1, odef)
        self.assertEqual(c1, c10)
        self.assertEqual(c1, cdef)
        # И никакого сырого значения.
        self.assertNotIn(_EMAIL, o1)
        self.assertNotIn(_INN, o1)
        # Каждая строка стала одинаковым «contact [EMAIL_1] ИНН [INN_1]».
        self.assertEqual(o1.count("[EMAIL_1]"), rows)
        self.assertEqual(o1.count("[INN_1]"), rows)

    def test_no_raw_leak_regardless_of_block_lines(self):
        rows = 7
        line = _line(3)
        for bl in (1, 3, 10, 2000):
            _, out = self._run(bl, line, rows)
            self.assertNotIn(_INN, out, "block_lines={0}".format(bl))
            self.assertNotIn("user3@ex.com", out, "block_lines={0}".format(bl))


class RedactFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def test_in_to_out_masks_and_returns_count(self):
        src, dst = self._path("in.txt"), self._path("out.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("line a" + "@" + "b.com\nline c" + "@" + "d.com\n")
        count = redact_file(src, dst)
        self.assertEqual(count, 2)
        with open(dst, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data, "line [EMAIL_1]\nline [EMAIL_2]\n")
        self.assertNotIn("@", data)

    def test_empty_file_in_to_out(self):
        src, dst = self._path("empty.txt"), self._path("empty_out.txt")
        open(src, "w").close()
        count = redact_file(src, dst)
        self.assertEqual(count, 0)
        with open(dst, encoding="utf-8") as f:
            self.assertEqual(f.read(), "")

    def test_single_line_file(self):
        src, dst = self._path("one.txt"), self._path("one_out.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("email " + _EMAIL)
        count = redact_file(src, dst)
        self.assertEqual(count, 1)
        with open(dst, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data, "email [EMAIL_1]")
        self.assertNotIn(_EMAIL, data)

    def test_block_lines_does_not_change_count_in_file(self):
        src = self._path("multi.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("".join(_line(i) for i in range(8)))
        c_small = redact_file(src, self._path("o_small.txt"), block_lines=1)
        c_big = redact_file(src, self._path("o_big.txt"), block_lines=2000)
        self.assertEqual(c_small, c_big)
        self.assertEqual(c_small, 16)


class MultiLineFindingWithinBlockTests(unittest.TestCase):
    """Блок PRIVATE KEY (несколько строк) ЦЕЛИКОМ внутри одного блока находится."""

    KEY = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA\n"
        "abcdEFGHijkl1234567890ZZZZ\n"
        "-----END PRIVATE KEY-----\n"
    )
    BODY = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA"

    def test_private_key_block_within_one_block_is_redacted(self):
        out = io.StringIO()
        # block_lines много больше числа строк ключа -> ключ целиком в одном блоке.
        count = redact_stream(
            io.StringIO(self.KEY), out, build_engine(), block_lines=2000
        )
        result = out.getvalue()
        self.assertEqual(count, 1)
        self.assertIn("[PRIVATE_KEY_1]", result)
        # Тело ключа не утекает.
        self.assertNotIn(self.BODY, result)
        self.assertNotIn("BEGIN PRIVATE KEY", result)


class BlockBoundarySplitLimitationTests(unittest.TestCase):
    """ЗАДОКУМЕНТИРОВАННОЕ ОГРАНИЧЕНИЕ: находка, разорванная ровно по границе
    блока, не детектируется и её тело утекает. Тест фиксирует это поведение,
    чтобы регрессия в любую сторону была замечена."""

    KEY = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA\n"
        "abcdEFGHijkl1234567890ZZZZ\n"
        "-----END PRIVATE KEY-----\n"
    )
    BODY = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA"

    def test_key_split_across_block_boundary_is_not_detected(self):
        # 4 строки, block_lines=2 -> ключ разрезан между блоком 1 (строки 0-1)
        # и блоком 2 (строки 2-3). Это известное ограничение.
        out = io.StringIO()
        count = redact_stream(
            io.StringIO(self.KEY), out, build_engine(), block_lines=2
        )
        result = out.getvalue()
        # Находка не зафиксирована.
        self.assertEqual(count, 0)
        # Тело ключа утекает целиком (документируем ограничение).
        self.assertIn(self.BODY, result)
        self.assertNotIn("[PRIVATE_KEY_1]", result)

    def test_same_key_detected_when_block_contains_whole_finding(self):
        # Контраст: при block_lines>=4 (весь ключ в одном блоке) — детектируется.
        out = io.StringIO()
        count = redact_stream(
            io.StringIO(self.KEY), out, build_engine(), block_lines=4
        )
        result = out.getvalue()
        self.assertEqual(count, 1)
        self.assertNotIn(self.BODY, result)


class BatchTests(unittest.TestCase):
    """batch.redact_one (топ-левел, picklable) и redact_files (serial + ProcessPool).

    ProcessPool-путь использует временные файлы и малое число воркеров (2)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _make(self, name: str, content: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_redact_one_returns_out_and_count(self):
        src = self._make("a.txt", "email " + _EMAIL + "\n")
        dst = os.path.join(self.dir, "a.out")
        out_path, count = redact_one((src, dst))
        self.assertEqual(out_path, dst)
        self.assertEqual(count, 1)
        with open(dst, encoding="utf-8") as f:
            data = f.read()
        self.assertEqual(data, "email [EMAIL_1]\n")
        self.assertNotIn(_EMAIL, data)

    def test_redact_files_empty_pairs(self):
        self.assertEqual(redact_files([]), {})

    def test_redact_files_single_file_serial(self):
        src = self._make("s.txt", "email " + _EMAIL + "\n")
        dst = os.path.join(self.dir, "s.out")
        # Один файл -> сериально (без ProcessPool).
        result = redact_files([(src, dst)])
        self.assertEqual(result, {dst: 1})

    def test_redact_files_workers_one_is_serial(self):
        src1 = self._make("w1.txt", "email " + _EMAIL + "\n")
        src2 = self._make("w2.txt", "no secrets at all\n")
        dst1 = os.path.join(self.dir, "w1.out")
        dst2 = os.path.join(self.dir, "w2.out")
        result = redact_files([(src1, dst1), (src2, dst2)], workers=1)
        self.assertEqual(result, {dst1: 1, dst2: 0})

    def test_redact_files_parallel_processpool(self):
        # Два файла, workers=2 -> реальный ProcessPoolExecutor.
        src1 = self._make("p1.txt", "email " + _EMAIL + "\n" + _INN_KW + " " + _INN + "\n")
        src2 = self._make("p2.txt", "")  # пустой -> 0 находок
        dst1 = os.path.join(self.dir, "p1.out")
        dst2 = os.path.join(self.dir, "p2.out")
        result = redact_files([(src1, dst1), (src2, dst2)], workers=2)
        self.assertEqual(result, {dst1: 2, dst2: 0})
        with open(dst1, encoding="utf-8") as f:
            data = f.read()
        self.assertNotIn(_EMAIL, data)
        self.assertNotIn(_INN, data)
        self.assertEqual(data, "email [EMAIL_1]\n" + _INN_KW + " [INN_1]\n")
        with open(dst2, encoding="utf-8") as f:
            self.assertEqual(f.read(), "")


if __name__ == "__main__":
    unittest.main()
