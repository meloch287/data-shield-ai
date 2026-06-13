"""Тесты для datashield.batch — параллельная редакция множества файлов.

Проверяем фактическое поведение redact_one / redact_files:
- redact_one((in, out)) редактирует один файл и возвращает (out, count);
- redact_files на нескольких tempfile-ах возвращает {out: count}, и каждый
  выходной файл корректно замаскирован (плейсхолдеры вместо сырых значений);
- workers=1 и одиночный файл идут последовательно;
- пустой список -> {};
- результат покрывает все входы.

ProcessPool-тест использует top-level picklable redact_one и небольшое число
воркеров (2); входные файлы создаются через tempfile.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from datashield.batch import redact_files, redact_one

# Сырые секретные значения собираем конкатенацией — чтобы скан-секретов не
# срабатывал на сам тест, и чтобы было видно, что плейсхолдер != оригинал.
_DOMAIN = "corp" + "." + "com"


def _email(local: str) -> str:
    return local + "@" + _DOMAIN


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


class RedactOneTests(unittest.TestCase):
    """redact_one редактирует один tempfile и возвращает (out, count)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ds_batch_one_")

    def _pair(self, name: str):
        in_path = os.path.join(self.tmp, name + ".txt")
        out_path = os.path.join(self.tmp, name + ".masked")
        return in_path, out_path

    def test_returns_outpath_and_count(self) -> None:
        in_path, out_path = self._pair("a")
        raw = _email("alice")
        _write(in_path, "contact " + raw + " today\n")

        result = redact_one((in_path, out_path))

        # Возвращается ровно кортеж (out_path, count).
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        returned_out, count = result
        self.assertEqual(returned_out, out_path)
        self.assertEqual(count, 1)

    def test_output_file_is_masked(self) -> None:
        in_path, out_path = self._pair("b")
        raw = _email("bob")
        _write(in_path, "email " + raw + " end\n")

        redact_one((in_path, out_path))

        masked = _read(out_path)
        # Сырое значение исчезло, плейсхолдер появился.
        self.assertNotIn(raw, masked)
        self.assertIn("[EMAIL_1]", masked)
        # Несекретный контекст сохранён.
        self.assertIn("email ", masked)
        self.assertIn(" end", masked)

    def test_per_file_placeholder_numbering(self) -> None:
        # Внутри одного файла нумерация плейсхолдеров идёт 1, 2, ...
        in_path, out_path = self._pair("c")
        raw1 = _email("first")
        raw2 = _email("second")
        _write(in_path, raw1 + " / " + raw2 + "\n")

        _, count = redact_one((in_path, out_path))

        self.assertEqual(count, 2)
        masked = _read(out_path)
        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[EMAIL_2]", masked)
        self.assertNotIn(raw1, masked)
        self.assertNotIn(raw2, masked)

    def test_clean_file_zero_count(self) -> None:
        in_path, out_path = self._pair("clean")
        _write(in_path, "nothing sensitive here at all\n")

        out, count = redact_one((in_path, out_path))

        self.assertEqual(out, out_path)
        self.assertEqual(count, 0)
        # Содержимое чистого файла проходит без изменений.
        self.assertEqual(_read(out_path), "nothing sensitive here at all\n")

    def test_output_file_actually_created(self) -> None:
        in_path, out_path = self._pair("created")
        _write(in_path, "plain text\n")
        self.assertFalse(os.path.exists(out_path))

        redact_one((in_path, out_path))

        self.assertTrue(os.path.exists(out_path))


class RedactFilesSerialTests(unittest.TestCase):
    """workers<=1 и одиночный файл идут последовательно (без ProcessPool)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ds_batch_serial_")

    def _make(self, name: str, body: str):
        in_path = os.path.join(self.tmp, name + ".txt")
        out_path = os.path.join(self.tmp, name + ".masked")
        _write(in_path, body)
        return in_path, out_path

    def test_empty_list_returns_empty_dict(self) -> None:
        self.assertEqual(redact_files([]), {})

    def test_single_file_goes_serial(self) -> None:
        # Один файл -> по коду последовательный путь (len(pairs) == 1).
        raw = _email("solo")
        in_path, out_path = self._make("solo", "x " + raw + " y\n")

        result = redact_files([(in_path, out_path)])

        self.assertEqual(result, {out_path: 1})
        masked = _read(out_path)
        self.assertIn("[EMAIL_1]", masked)
        self.assertNotIn(raw, masked)

    def test_workers_one_forces_serial(self) -> None:
        raw_a = _email("aaa")
        raw_b = _email("bbb")
        pa = self._make("a", "line " + raw_a + "\n")
        pb = self._make("b", "line " + raw_b + "\n")

        result = redact_files([pa, pb], workers=1)

        # Результат покрывает все входы.
        self.assertEqual(set(result), {pa[1], pb[1]})
        self.assertEqual(result[pa[1]], 1)
        self.assertEqual(result[pb[1]], 1)
        self.assertNotIn(raw_a, _read(pa[1]))
        self.assertNotIn(raw_b, _read(pb[1]))
        self.assertIn("[EMAIL_1]", _read(pa[1]))
        self.assertIn("[EMAIL_1]", _read(pb[1]))

    def test_workers_zero_forces_serial(self) -> None:
        raw = _email("zero")
        p = self._make("z", "z " + raw + " z\n")

        result = redact_files([p], workers=0)

        self.assertEqual(result, {p[1]: 1})
        self.assertNotIn(raw, _read(p[1]))

    def test_mixed_counts_serial(self) -> None:
        # Файл с двумя находками и файл без находок.
        raw1 = _email("one")
        raw2 = _email("two")
        dirty = self._make("dirty", raw1 + " and " + raw2 + "\n")
        clean = self._make("clean", "absolutely nothing here\n")

        result = redact_files([dirty, clean], workers=1)

        self.assertEqual(result[dirty[1]], 2)
        self.assertEqual(result[clean[1]], 0)
        masked_dirty = _read(dirty[1])
        self.assertIn("[EMAIL_1]", masked_dirty)
        self.assertIn("[EMAIL_2]", masked_dirty)
        self.assertEqual(_read(clean[1]), "absolutely nothing here\n")


class RedactFilesParallelTests(unittest.TestCase):
    """ProcessPool: несколько tempfile-ов, маленькое число воркеров (2)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ds_batch_par_")

    def _make(self, name: str, body: str):
        in_path = os.path.join(self.tmp, name + ".txt")
        out_path = os.path.join(self.tmp, name + ".masked")
        _write(in_path, body)
        return in_path, out_path

    def test_parallel_maps_all_inputs(self) -> None:
        pairs = []
        raws = []
        for i in range(3):
            raw = _email("user" + str(i))
            raws.append(raw)
            pairs.append(self._make("p" + str(i), "row " + raw + " done\n"))

        # Небольшое число воркеров (2), несколько файлов -> ProcessPool.
        result = redact_files(pairs, workers=2)

        # Карта результатов покрывает ВСЕ входы.
        self.assertEqual(set(result), {p[1] for p in pairs})
        # Каждый выход корректно замаскирован.
        for (_in_path, out_path), raw in zip(pairs, raws):
            self.assertEqual(result[out_path], 1)
            masked = _read(out_path)
            self.assertNotIn(raw, masked)
            self.assertIn("[EMAIL_1]", masked)
            self.assertIn("row ", masked)
            self.assertIn(" done", masked)

    def test_parallel_counts_match_per_file(self) -> None:
        raw_a = _email("xa")
        raw_b1 = _email("xb1")
        raw_b2 = _email("xb2")
        pa = self._make("ca", "single " + raw_a + "\n")
        pb = self._make("cb", raw_b1 + " plus " + raw_b2 + "\n")

        result = redact_files([pa, pb], workers=2)

        self.assertEqual(result[pa[1]], 1)
        self.assertEqual(result[pb[1]], 2)
        masked_b = _read(pb[1])
        self.assertIn("[EMAIL_1]", masked_b)
        self.assertIn("[EMAIL_2]", masked_b)
        self.assertNotIn(raw_b1, masked_b)
        self.assertNotIn(raw_b2, masked_b)


if __name__ == "__main__":
    unittest.main()
