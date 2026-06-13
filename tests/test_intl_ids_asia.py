"""Asia international ID detectors/validators for Data Shield AI (Block C).

Focus: India AADHAAR (Verhoeff), India PAN_IN, China CHINA_ID (mod-11 / X check
digit) and keyword-gated CHINA_MOBILE.

These tests assert the ACTUAL behaviour of the real sources:
- datashield/validators_intl.py: verhoeff_check, validate_aadhaar, validate_china_id
- datashield/detectors/intl_ids.py: AADHAAR, PAN_IN, CHINA_ID (default-on),
  CHINA_MOBILE (keyword-gated via confidence boost)
- public API datashield.scan / datashield.redact (default min_confidence=0.7)

Valid Aadhaar and China-ID vectors are CONSTRUCTED here by computing the check
digit with the very algorithm the validators use, rather than hardcoding
unverified samples (per task instructions).
"""
from __future__ import annotations

import unittest

from datashield import redact, scan
from datashield.validators_intl import (
    validate_aadhaar,
    validate_china_id,
    verhoeff_check,
)


# --------------------------------------------------------------------------- #
# Sample builders — derive a VALID id from the real check-digit algorithms.    #
# --------------------------------------------------------------------------- #
def make_aadhaar(body11: str) -> str:
    """11 body digits -> 12-digit Aadhaar with the appended Verhoeff check digit."""
    assert len(body11) == 11 and body11.isdigit()
    for d in "0123456789":
        if verhoeff_check(body11 + d):
            return body11 + d
    raise AssertionError("no Verhoeff check digit found")  # pragma: no cover


# China-ID weights/codes mirror validate_china_id in validators_intl.py.
_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_CODES = "10X98765432"


def make_china_id(body17: str) -> str:
    """17 body digits -> 18-char China resident ID with computed check char."""
    assert len(body17) == 17 and body17.isdigit()
    total = sum(int(body17[i]) * _CN_WEIGHTS[i] for i in range(17))
    return body17 + _CN_CODES[total % 11]


def _china_id_with_check(target: str) -> str:
    """Find an 18-char valid China ID whose check char equals `target`."""
    base = "11010119900307"  # region + birthdate prefix (14 digits)
    for tail in range(0, 1000):
        cid = make_china_id(base + f"{tail:03d}")
        if cid[-1] == target:
            return cid
    raise AssertionError(f"no China ID with check char {target!r}")  # pragma: no cover


def _flip_last_digit(s: str) -> str:
    """Return s with its final digit changed (to break the checksum)."""
    last = s[-1]
    repl = "0" if last != "0" else "1"
    return s[:-1] + repl


def types(text: str):
    return {f.type for f in scan(text)}


# A reusable known-good Aadhaar and China IDs, built once.
VALID_AADHAAR = make_aadhaar("23456789012")          # first digit 2 (not 0/1)
VALID_CHINA_NUM = _china_id_with_check("3")          # numeric check char (any)
VALID_CHINA_X = _china_id_with_check("X")            # X check char


# --------------------------------------------------------------------------- #
# Verhoeff core / Aadhaar validator                                            #
# --------------------------------------------------------------------------- #
class TestAadhaarValidator(unittest.TestCase):
    def test_constructed_sample_is_valid(self):
        self.assertEqual(len(VALID_AADHAAR), 12)
        self.assertTrue(VALID_AADHAAR.isdigit())
        self.assertTrue(verhoeff_check(VALID_AADHAAR))
        self.assertTrue(validate_aadhaar(VALID_AADHAAR))

    def test_first_digit_not_zero(self):
        self.assertNotIn(VALID_AADHAAR[0], "01")

    def test_tampered_check_digit_invalid(self):
        self.assertFalse(validate_aadhaar(_flip_last_digit(VALID_AADHAAR)))

    def test_spaced_form_accepted(self):
        spaced = VALID_AADHAAR[:4] + " " + VALID_AADHAAR[4:8] + " " + VALID_AADHAAR[8:]
        self.assertIn(" ", spaced)
        self.assertTrue(validate_aadhaar(spaced))

    def test_first_digit_zero_or_one_rejected_despite_valid_verhoeff(self):
        # The "first digit not 0/1" rule is independent of the checksum.
        for n in ("100000000004", "000000000003"):
            self.assertTrue(verhoeff_check(n), n)
            self.assertFalse(validate_aadhaar(n), n)

    def test_wrong_length_rejected(self):
        self.assertFalse(validate_aadhaar(VALID_AADHAAR[:-1]))   # 11 digits
        self.assertFalse(validate_aadhaar(VALID_AADHAAR + "0"))  # 13 digits


# --------------------------------------------------------------------------- #
# AADHAAR detector via public scan() — default-on, structure + Verhoeff.       #
# --------------------------------------------------------------------------- #
class TestAadhaarDetector(unittest.TestCase):
    def test_valid_plain_detected(self):
        self.assertIn("AADHAAR", types("id " + VALID_AADHAAR))

    def test_valid_spaced_form_detected(self):
        spaced = VALID_AADHAAR[:4] + " " + VALID_AADHAAR[4:8] + " " + VALID_AADHAAR[8:]
        self.assertIn("AADHAAR", types("id " + spaced))

    def test_tampered_not_detected_as_aadhaar(self):
        # Checksum failure -> validator rejects -> no AADHAAR finding.
        self.assertNotIn("AADHAAR", types("id " + _flip_last_digit(VALID_AADHAAR)))

    def test_redact_replaces_aadhaar(self):
        result = redact("Aadhaar " + VALID_AADHAAR)
        self.assertNotIn(VALID_AADHAAR, result.masked_text)
        self.assertIn("AADHAAR", result.masked_text)


# --------------------------------------------------------------------------- #
# India PAN_IN detector — pure shape, no checksum, default-on.                 #
# --------------------------------------------------------------------------- #
class TestPanInDetector(unittest.TestCase):
    def test_valid_shape_detected(self):
        self.assertIn("PAN_IN", types("PAN ABCDE1234F"))

    def test_lowercase_not_detected(self):
        # Pattern requires uppercase [A-Z]{5}...[A-Z]; lowercase must not fire.
        self.assertNotIn("PAN_IN", types("pan abcde1234f"))

    def test_wrong_shape_not_detected(self):
        # 4 leading letters instead of 5 breaks the pattern.
        self.assertNotIn("PAN_IN", types("PAN ABCD1234F"))

    def test_digits_in_letter_slot_not_detected(self):
        self.assertNotIn("PAN_IN", types("PAN ABCDE12345"))


# --------------------------------------------------------------------------- #
# China resident ID validator + detector.                                      #
# --------------------------------------------------------------------------- #
class TestChinaIdValidator(unittest.TestCase):
    def test_numeric_check_sample_valid(self):
        self.assertEqual(len(VALID_CHINA_NUM), 18)
        self.assertTrue(validate_china_id(VALID_CHINA_NUM))

    def test_x_check_sample_valid(self):
        self.assertEqual(VALID_CHINA_X[-1], "X")
        self.assertTrue(validate_china_id(VALID_CHINA_X))

    def test_lowercase_x_accepted(self):
        # validator upcases input, so a trailing lowercase 'x' still validates.
        self.assertTrue(validate_china_id(VALID_CHINA_X[:-1] + "x"))

    def test_tampered_invalid(self):
        self.assertFalse(validate_china_id(_flip_last_digit(VALID_CHINA_NUM)))

    def test_wrong_length_rejected(self):
        self.assertFalse(validate_china_id(VALID_CHINA_NUM[:-1]))    # 17 chars
        self.assertFalse(validate_china_id(VALID_CHINA_NUM + "0"))   # 19 chars


class TestChinaIdDetector(unittest.TestCase):
    def test_numeric_check_detected(self):
        self.assertIn("CHINA_ID", types("id " + VALID_CHINA_NUM))

    def test_x_check_detected(self):
        self.assertIn("CHINA_ID", types("id " + VALID_CHINA_X))

    def test_lowercase_x_detected(self):
        # Detector regex allows [Xx]; validator upcases -> still a CHINA_ID.
        self.assertIn("CHINA_ID", types("id " + VALID_CHINA_X[:-1] + "x"))

    def test_tampered_not_detected(self):
        self.assertNotIn("CHINA_ID", types("id " + _flip_last_digit(VALID_CHINA_NUM)))


# --------------------------------------------------------------------------- #
# CHINA_MOBILE — keyword-gated: base confidence 0.5 is below the engine's      #
# default min_confidence 0.7, so it only surfaces when a keyword boosts it.    #
# --------------------------------------------------------------------------- #
class TestChinaMobileKeywordGating(unittest.TestCase):
    MOBILE = "13800138000"  # valid 11-digit form: 1[3-9] + 9 digits

    def test_no_keyword_not_detected(self):
        self.assertNotIn("CHINA_MOBILE", types("contact " + self.MOBILE))

    def test_keyword_mobile_detected(self):
        self.assertIn("CHINA_MOBILE", types("mobile: " + self.MOBILE))

    def test_keyword_cjk_shouji_detected(self):
        self.assertIn("CHINA_MOBILE", types("手机 " + self.MOBILE))

    def test_keyword_phone_detected(self):
        self.assertIn("CHINA_MOBILE", types("phone " + self.MOBILE))

    def test_redact_masks_mobile_with_keyword(self):
        result = redact("mobile " + self.MOBILE)
        self.assertNotIn(self.MOBILE, result.masked_text)
        self.assertIn("CHINA_MOBILE", result.masked_text)

    def test_redact_keeps_mobile_without_keyword(self):
        # Below threshold -> left untouched (not a confident PII match).
        result = redact("number " + self.MOBILE)
        self.assertIn(self.MOBILE, result.masked_text)


if __name__ == "__main__":
    unittest.main()
