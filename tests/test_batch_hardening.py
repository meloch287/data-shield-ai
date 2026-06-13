"""Регресс на изоляцию ошибок в батче (адверсариал-аудит Блока I)."""
import os
import tempfile
import unittest

from datashield.batch import redact_files, redact_one


class BatchErrorIsolationTests(unittest.TestCase):
    def test_missing_file_returns_minus_one_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x.masked")
            result = redact_one((os.path.join(d, "NOPE.txt"), out))
            self.assertEqual(result, (out, -1))

    def test_one_bad_file_does_not_break_the_batch(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.txt")
            with open(good, "w", encoding="utf-8") as fh:
                fh.write("email a@b.com")
            good_out = os.path.join(d, "good.masked")
            bad_out = os.path.join(d, "bad.masked")
            res = redact_files(
                [(good, good_out), (os.path.join(d, "MISSING.txt"), bad_out)],
                workers=1,
            )
            self.assertEqual(res[good_out], 1)
            self.assertEqual(res[bad_out], -1)
            with open(good_out, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "email [EMAIL_1]")


if __name__ == "__main__":
    unittest.main()
