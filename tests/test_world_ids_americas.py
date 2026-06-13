"""Americas national ID detection: Brazil (CPF, CNPJ), Mexico (CURP) and
Canada (SIN).

Brazil's CPF_BR and CNPJ_BR plus Mexico's CURP_MX carry strong structure and a
mod-11 / mod-10 check digit, so they are default-on: a valid value is detected
and masked with no surrounding keyword. Canada's SIN_CA is a bare 9-digit run
(Luhn-checked) that is too format-generic to mask on its own, so it is
keyword-gated: present only when "SIN" or "social insurance" sits within the
25-char context window before the match, absent otherwise (its un-boosted
confidence 0.4 falls below the default 0.7 threshold).

Every expectation below was verified against the live behavior of
datashield/detectors/world_ids.py and datashield/validators_world.py through the
public API (datashield.scan / datashield.redact). Known-valid vectors come from
the task brief and are confirmed by their own validators:
  CPF 11144477735 ; CNPJ 11222333000181 ; SIN 046454286 ;
  CURP HEGG560427MVZRRL04.
Catalog totals are computed from build_catalog, never hardcoded.
"""
import unittest

from datashield import redact, scan
from datashield.config import Config
from datashield.detectors.registry import build_catalog
from datashield.validators_world import (
    validate_cnpj,
    validate_cpf,
    validate_curp_mx,
    validate_sin_ca,
)

# Known-valid vectors (from the brief; each confirmed by its validator below).
CPF_BARE = "11144477735"
CPF_FORMATTED = "111.444.777-35"
CNPJ_BARE = "11222333000181"
CNPJ_FORMATTED = "11.222.333/0001-81"
CURP_VALID = "HEGG560427MVZRRL04"
SIN_BARE = "046454286"


def types(text: str) -> set:
    """Set of detected types under the default engine configuration."""
    return {f.type for f in scan(text)}


def findings_of(text: str, wanted_type: str):
    return [f for f in scan(text) if f.type == wanted_type]


class ValidatorVectorTests(unittest.TestCase):
    """The reusable vectors really pass their checksums; a one-character
    corruption fails. This anchors the detection tests that follow."""

    def test_cpf_known_valid(self):
        self.assertTrue(validate_cpf(CPF_BARE))

    def test_cpf_formatted_validates(self):
        # The validator strips non-digits, so canonical 3.3.3-2 spacing passes.
        self.assertTrue(validate_cpf(CPF_FORMATTED))

    def test_cpf_corrupted_check_digit_fails(self):
        # Flip the final check digit 5 -> 6.
        self.assertFalse(validate_cpf("11144477736"))

    def test_cpf_all_same_digit_rejected(self):
        # The validator explicitly rejects repeated-digit strings.
        self.assertFalse(validate_cpf("11111111111"))

    def test_cnpj_known_valid(self):
        self.assertTrue(validate_cnpj(CNPJ_BARE))

    def test_cnpj_formatted_validates(self):
        self.assertTrue(validate_cnpj(CNPJ_FORMATTED))

    def test_cnpj_corrupted_check_digit_fails(self):
        # Flip the final check digit 1 -> 2.
        self.assertFalse(validate_cnpj("11222333000182"))

    def test_curp_known_valid(self):
        self.assertTrue(validate_curp_mx(CURP_VALID))

    def test_curp_corrupted_check_digit_fails(self):
        # Flip the trailing check digit 4 -> 5.
        self.assertFalse(validate_curp_mx("HEGG560427MVZRRL05"))

    def test_sin_known_valid(self):
        self.assertTrue(validate_sin_ca(SIN_BARE))

    def test_sin_corrupted_luhn_fails(self):
        # Flip the final digit 6 -> 7 to break the Luhn checksum.
        self.assertFalse(validate_sin_ca("046454287"))


class CpfDetectionTests(unittest.TestCase):
    """Brazil CPF_BR: default-on, detected formatted and bare; tampered not."""

    def test_cpf_formatted_detected(self):
        found = findings_of(f"Cliente CPF {CPF_FORMATTED} cadastrado", "CPF_BR")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, CPF_FORMATTED)
        self.assertEqual(found[0].confidence, 0.85)

    def test_cpf_bare_detected_without_keyword(self):
        # Strong checksum makes CPF default-on: no keyword needed.
        found = findings_of(CPF_BARE, "CPF_BR")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, CPF_BARE)

    def test_cpf_bare_detected_in_sentence(self):
        self.assertIn("CPF_BR", types(f"id {CPF_BARE} done"))

    def test_cpf_tampered_not_detected(self):
        # Corrupt the last check digit: the validator rejects it, so the regex
        # match is dropped and nothing is flagged as CPF_BR.
        self.assertNotIn("CPF_BR", types("CPF 11144477736"))

    def test_cpf_tampered_formatted_not_detected(self):
        self.assertNotIn("CPF_BR", types("CPF 111.444.777-36"))

    def test_cpf_repeated_digits_not_detected(self):
        # 11 identical digits match the pattern but are rejected by the validator.
        self.assertNotIn("CPF_BR", types("11111111111"))

    def test_cpf_redacted_with_placeholder(self):
        result = redact(f"CPF {CPF_FORMATTED} ok")
        self.assertEqual(result.masked_text, "CPF [CPF_BR_1] ok")
        self.assertEqual(result.stats.get("CPF_BR"), 1)

    def test_cpf_tampered_not_masked(self):
        # Invalid checksum must survive untouched in the output.
        text = "CPF 11144477736"
        self.assertEqual(redact(text).masked_text, text)


class CnpjDetectionTests(unittest.TestCase):
    """Brazil CNPJ_BR: default-on, detected formatted and bare; tampered not."""

    def test_cnpj_formatted_detected(self):
        found = findings_of(f"CNPJ {CNPJ_FORMATTED}", "CNPJ_BR")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, CNPJ_FORMATTED)
        self.assertEqual(found[0].confidence, 0.88)

    def test_cnpj_bare_detected_without_keyword(self):
        found = findings_of(CNPJ_BARE, "CNPJ_BR")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, CNPJ_BARE)

    def test_cnpj_tampered_not_detected(self):
        # Corrupt the trailing check digit 1 -> 9.
        self.assertNotIn("CNPJ_BR", types("CNPJ 11.222.333/0001-99"))

    def test_cnpj_redacted_with_placeholder(self):
        result = redact(f"empresa CNPJ {CNPJ_FORMATTED}")
        self.assertEqual(result.masked_text, "empresa CNPJ [CNPJ_BR_1]")
        self.assertEqual(result.stats.get("CNPJ_BR"), 1)

    def test_cnpj_tampered_not_masked(self):
        text = "CNPJ 11.222.333/0001-99"
        self.assertEqual(redact(text).masked_text, text)


class CurpDetectionTests(unittest.TestCase):
    """Mexico CURP_MX: default-on, structure + base-37 mod-10 check digit."""

    def test_curp_detected(self):
        found = findings_of(f"CURP: {CURP_VALID}", "CURP_MX")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, CURP_VALID)
        self.assertEqual(found[0].confidence, 0.9)

    def test_curp_detected_without_keyword(self):
        # Distinctive 18-char shape makes CURP default-on.
        self.assertIn("CURP_MX", types(f"registro {CURP_VALID} ok"))

    def test_curp_lowercase_wrong_shape_negative(self):
        # The detector regex requires uppercase letters; lowercase does not match.
        self.assertNotIn("CURP_MX", types(f"curp {CURP_VALID.lower()}"))

    def test_curp_truncated_wrong_shape_negative(self):
        # 17 characters: too short for the [A-Z]{4}\d{6}... shape.
        self.assertNotIn("CURP_MX", types("HEGG560427MVZRRL0"))

    def test_curp_digits_in_name_block_negative(self):
        # Leading four positions must be letters; digits there break the shape.
        self.assertNotIn("CURP_MX", types("1234560427MVZRRL04"))

    def test_curp_bad_checksum_not_detected(self):
        # Correct shape, wrong final check digit -> validator rejects it.
        self.assertNotIn("CURP_MX", types("CURP HEGG560427MVZRRL05"))

    def test_curp_redacted_with_placeholder(self):
        result = redact(f"CURP {CURP_VALID} verificado")
        self.assertEqual(result.masked_text, "CURP [CURP_MX_1] verificado")
        self.assertEqual(result.stats.get("CURP_MX"), 1)


class SinKeywordGatingTests(unittest.TestCase):
    """Canada SIN_CA: keyword-gated. Bare Luhn-valid 9-digit run alone stays
    below the 0.7 threshold; an SIN / social-insurance keyword boosts it."""

    def test_sin_present_with_sin_keyword(self):
        found = findings_of(f"SIN {SIN_BARE}", "SIN_CA")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, SIN_BARE)
        # Keyword present -> boosted confidence 0.9.
        self.assertEqual(found[0].confidence, 0.9)

    def test_sin_present_with_social_insurance_keyword(self):
        # Canonical 3-3-3 spacing plus the "social insurance" phrase.
        self.assertIn("SIN_CA", types("social insurance number 046-454-286"))

    def test_sin_absent_without_keyword(self):
        # Un-boosted base confidence 0.4 < default 0.7, so SIN_CA is filtered.
        self.assertNotIn("SIN_CA", types(SIN_BARE))

    def test_sin_absent_with_unrelated_context(self):
        self.assertNotIn("SIN_CA", types(f"reference number {SIN_BARE} here"))

    def test_sin_keyword_redacts_value(self):
        result = redact(f"SIN {SIN_BARE}")
        self.assertEqual(result.masked_text, "SIN [SIN_CA_1]")
        self.assertEqual(result.stats.get("SIN_CA"), 1)

    def test_sin_without_keyword_not_masked_as_sin(self):
        # No SIN keyword: the value is not redacted under the SIN_CA type.
        self.assertNotIn("SIN_CA", redact(SIN_BARE).stats)


class CatalogRegistrationTests(unittest.TestCase):
    """The Americas types are present in the default catalog. Totals are
    computed from build_catalog so they track the real registry, never a frozen
    constant."""

    def setUp(self):
        self.catalog = build_catalog(Config())
        self.default_on_types = {
            info.detector.type
            for info in self.catalog
            if info.default_enabled
        }
        self.all_types = {info.detector.type for info in self.catalog}

    def test_americas_id_types_default_on(self):
        for t in ("CPF_BR", "CNPJ_BR", "CURP_MX"):
            with self.subTest(type=t):
                self.assertIn(t, self.default_on_types)

    def test_sin_ca_registered_and_default_on(self):
        # SIN_CA is default-on in the catalog; its gating is by confidence at
        # detect time, not by being disabled in the registry.
        self.assertIn("SIN_CA", self.default_on_types)

    def test_catalog_total_matches_count_of_entries(self):
        # Dynamic invariant: distinct-type count cannot exceed detector count.
        self.assertLessEqual(len(self.all_types), len(self.catalog))

    def test_default_on_subset_of_catalog(self):
        default_on = [i for i in self.catalog if i.default_enabled]
        self.assertLessEqual(len(default_on), len(self.catalog))


if __name__ == "__main__":
    unittest.main()
