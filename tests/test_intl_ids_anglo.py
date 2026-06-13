"""Anglo-American international ID detectors: UK (NHS, sort code) and US (ABA
routing, passport, ITIN).

These detectors are keyword-gated: the underlying patterns are format-generic
(bare digit runs), so a bare number must NOT be masked at the default confidence
threshold (0.7). A matching keyword within the 25-char context window before the
match boosts confidence (~0.9) so the value is detected and masked.

All expectations below were verified against the live behavior of
datashield/detectors/intl_ids.py and datashield/validators_intl.py, accessed
through the public API (datashield.scan / datashield.redact). The known-valid
vectors (NHS 9434765919, ABA 021000021) are confirmed by their validators.
"""
import unittest

from datashield import redact, scan
from datashield.validators_intl import validate_aba, validate_nhs


def types(text: str) -> set:
    """Set of detected types under the default engine configuration."""
    return {f.type for f in scan(text)}


def findings_of(text: str, wanted_type: str):
    return [f for f in scan(text) if f.type == wanted_type]


class ValidatorVectorTests(unittest.TestCase):
    """The reusable known-valid vectors really pass their checksums, and a
    one-digit corruption fails. This anchors the rest of the suite."""

    def test_nhs_known_valid(self):
        self.assertTrue(validate_nhs("9434765919"))

    def test_nhs_corrupted_check_digit_fails(self):
        # Flip the final (check) digit: 9 -> 8.
        self.assertFalse(validate_nhs("9434765918"))

    def test_nhs_spaces_are_ignored_by_validator(self):
        # The NHS validator strips non-digits, so the canonical 3-3-4 spacing
        # of the same number still validates.
        self.assertTrue(validate_nhs("943 476 5919"))

    def test_aba_known_valid(self):
        self.assertTrue(validate_aba("021000021"))

    def test_aba_corrupted_check_fails(self):
        # 021000021 is valid; 021000022 breaks the mod-10 weighted sum.
        self.assertFalse(validate_aba("021000022"))


class NhsUkDetectorTests(unittest.TestCase):
    """NHS_UK: 10 digits (optionally 3-3-4 spaced), mod-11 checksum, gated on a
    standalone 'NHS' keyword in the preceding context window."""

    def test_detected_with_keyword(self):
        self.assertIn("NHS_UK", types("NHS 9434765919"))

    def test_absent_without_keyword(self):
        # Bare number, valid checksum, but no 'NHS' nearby -> base confidence
        # 0.5 < default 0.7 -> not surfaced.
        self.assertNotIn("NHS_UK", types("reference 9434765919"))
        self.assertEqual(types("order 9434765919 shipped"), set())

    def test_bad_checksum_not_detected_even_with_keyword(self):
        # Validator rejects the corrupted number, so the detector yields nothing
        # regardless of the keyword.
        self.assertNotIn("NHS_UK", types("NHS 9434765918"))

    def test_spaced_form_detected_with_keyword(self):
        result = findings_of("NHS 943 476 5919", "NHS_UK")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "943 476 5919")

    def test_keyword_outside_window_not_boosted(self):
        # The keyword window is 25 chars before the match. Push 'NHS' far away
        # and the boost no longer applies, so the value drops below threshold.
        far = "NHS " + "x" * 40 + " 9434765919"
        self.assertNotIn("NHS_UK", types(far))

    def test_confidence_is_boosted_with_keyword(self):
        result = findings_of("NHS 9434765919", "NHS_UK")
        self.assertEqual(len(result), 1)
        self.assertGreaterEqual(result[0].confidence, 0.7)

    def test_redacted_with_placeholder(self):
        out = redact("Patient NHS 9434765919 admitted").masked_text
        self.assertEqual(out, "Patient NHS [NHS_UK_1] admitted")

    def test_bare_number_not_redacted(self):
        out = redact("order 9434765919 shipped").masked_text
        self.assertEqual(out, "order 9434765919 shipped")


class UkSortCodeDetectorTests(unittest.TestCase):
    """UK_SORT_CODE: NN-NN-NN, gated on a 'sort code' / 'sort-code' keyword."""

    def test_detected_with_keyword(self):
        self.assertIn("UK_SORT_CODE", types("sort code 12-34-56"))

    def test_detected_with_hyphenated_keyword(self):
        self.assertIn("UK_SORT_CODE", types("sort-code 12-34-56"))

    def test_absent_without_keyword(self):
        self.assertNotIn("UK_SORT_CODE", types("value 12-34-56"))

    def test_value_captured(self):
        result = findings_of("sort code 12-34-56", "UK_SORT_CODE")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "12-34-56")

    def test_redacted_with_placeholder(self):
        out = redact("Branch sort code 12-34-56 ok").masked_text
        self.assertEqual(out, "Branch sort code [UK_SORT_CODE_1] ok")

    def test_bare_sort_code_not_redacted(self):
        out = redact("value 12-34-56 here").masked_text
        self.assertEqual(out, "value 12-34-56 here")


class AbaRoutingDetectorTests(unittest.TestCase):
    """ABA_ROUTING: 9 digits, mod-10 weighted checksum, gated on
    'routing' or a standalone 'ABA' keyword."""

    def test_detected_with_routing_keyword(self):
        self.assertIn("ABA_ROUTING", types("routing 021000021"))

    def test_detected_with_aba_keyword(self):
        self.assertIn("ABA_ROUTING", types("ABA 021000021"))

    def test_keyword_is_case_insensitive(self):
        self.assertIn("ABA_ROUTING", types("ROUTING 021000021"))

    def test_absent_without_keyword(self):
        self.assertNotIn("ABA_ROUTING", types("number 021000021"))
        self.assertEqual(types("code 021000021 here"), set())

    def test_bad_checksum_not_detected_even_with_keyword(self):
        # Valid 9-digit format but failing mod-10 sum: validator rejects it.
        self.assertNotIn("ABA_ROUTING", types("routing 021000022"))
        self.assertNotIn("ABA_ROUTING", types("routing 123456789"))

    def test_redacted_with_placeholder(self):
        out = redact("Bank routing 021000021 confirmed").masked_text
        self.assertEqual(out, "Bank routing [ABA_ROUTING_1] confirmed")

    def test_bare_number_not_redacted(self):
        out = redact("code 021000021 here").masked_text
        self.assertEqual(out, "code 021000021 here")


class UsPassportDetectorTests(unittest.TestCase):
    """US_PASSPORT: leading alnum + 8 digits, gated on a 'passport' keyword.
    No checksum -- structure + keyword only."""

    def test_letter_led_detected_with_keyword(self):
        self.assertIn("US_PASSPORT", types("passport A12345678"))

    def test_digit_led_detected_with_keyword(self):
        # The pattern's first character is [A-Z0-9], so an all-digit value also
        # matches under the 'passport' keyword.
        self.assertIn("US_PASSPORT", types("passport 021000021"))

    def test_absent_without_keyword(self):
        self.assertNotIn("US_PASSPORT", types("A12345678"))
        self.assertEqual(types("A12345678"), set())

    def test_value_captured(self):
        result = findings_of("passport A12345678", "US_PASSPORT")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "A12345678")

    def test_redacted_with_placeholder(self):
        out = redact("Travel passport A12345678 valid").masked_text
        self.assertEqual(out, "Travel passport [US_PASSPORT_1] valid")


class UsItinDetectorTests(unittest.TestCase):
    """US_ITIN: 9NN-NN-NNNN (must start with 9), gated on an 'ITIN' keyword."""

    def test_detected_with_keyword(self):
        self.assertIn("US_ITIN", types("ITIN 912-34-5678"))

    def test_absent_without_keyword(self):
        self.assertNotIn("US_ITIN", types("912-34-5678"))
        self.assertEqual(types("912-34-5678"), set())

    def test_must_start_with_nine(self):
        # A leading 8 does not match the ITIN structure even with the keyword.
        self.assertNotIn("US_ITIN", types("ITIN 812-34-5678"))

    def test_value_captured(self):
        result = findings_of("ITIN 912-34-5678", "US_ITIN")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "912-34-5678")

    def test_redacted_with_placeholder(self):
        out = redact("Filing ITIN 912-34-5678 done").masked_text
        self.assertEqual(out, "Filing ITIN [US_ITIN_1] done")


class KeywordGatingCrossCheckTests(unittest.TestCase):
    """The defining property of this family: a bare, keyword-less value of any
    of these formats must leave the text untouched after redaction."""

    def test_bare_values_pass_through_redaction(self):
        samples = [
            "9434765919",   # NHS, valid checksum, no keyword
            "021000021",    # ABA, valid checksum, no keyword
            "12-34-56",     # UK sort code, no keyword
            "912-34-5678",  # ITIN structure, no keyword
        ]
        for raw in samples:
            with self.subTest(value=raw):
                text = f"plain line {raw} end"
                self.assertEqual(redact(text).masked_text, text)

    def test_wrong_keyword_does_not_unlock_other_detector(self):
        # 'passport' near an ABA-valid number surfaces it as US_PASSPORT (shared
        # 9-char shape) but never as ABA_ROUTING, since 'routing'/'ABA' is absent.
        detected = types("passport 021000021")
        self.assertIn("US_PASSPORT", detected)
        self.assertNotIn("ABA_ROUTING", detected)


if __name__ == "__main__":
    unittest.main()
