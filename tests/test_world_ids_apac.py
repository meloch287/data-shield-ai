"""APAC + crypto world-ID detection tests for Data Shield AI (Block L).

These tests assert the ACTUAL behaviour of the real sources, read first:

- datashield/validators_world.py: validate_cpf, validate_cnpj, validate_sin_ca,
  validate_tfn_au, validate_mynumber_jp, validate_rrn_kr, validate_curp_mx,
  validate_vin (ISO 3779).
- datashield/detectors/world_ids.py: CPF_BR, CNPJ_BR, CURP_MX, TRON_ADDRESS are
  default-on (strong checksum/structure). RRN_KR, VIN, SIN_CA, TFN_AU,
  MYNUMBER_JP, SOLANA_ADDRESS are keyword-gated (base confidence 0.4 < default
  0.7, boosted to 0.85/0.9 when a keyword sits in the preceding window) — their
  single check covers too few positions to be safe default-on (RRN ~9%, VIN ~9%
  of random tokens pass), so a keyword is required. TRON is checksum-validated
  (base58check, version 0x41), so it stays default-on safely.
- datashield/detectors/secrets.py: STRIPE_WEBHOOK (whsec_), VAULT_TOKEN (hvs.),
  DOPPLER_TOKEN (dp.st/pt/ct.), PLANETSCALE_TOKEN (pscale_pw_/tkn_),
  LINEAR_TOKEN (lin_api_).
- datashield/taxonomy.py: BR/CA/AU/JP/KR/MX + VIN -> government_id;
  TRON/SOLANA -> crypto; the new secrets -> secret.
- public API datashield.scan / datashield.redact (default min_confidence=0.7).

Valid TFN / MyNumber / RRN vectors are CONSTRUCTED here by appending the check
digit computed with the very algorithm each validator uses (rather than
hardcoding unverified samples). KNOWN-VALID vectors from the task spec
(CPF/CNPJ/SIN/VIN/CURP) are also exercised against the real validators.

Catalog totals are computed dynamically from build_catalog (not hardcoded).
"""
from __future__ import annotations

import unittest

from datashield import redact, scan
from datashield.config import Config
from datashield.detectors.registry import build_catalog
from datashield.taxonomy import category_of, severity_of
from datashield.validators import validate_ogrn
from datashield.validators_world import (
    validate_cnpj,
    validate_cpf,
    validate_curp_mx,
    validate_mynumber_jp,
    validate_rrn_kr,
    validate_sin_ca,
    validate_tfn_au,
    validate_tron,
    validate_vin,
)

# --------------------------------------------------------------------------- #
# KNOWN-VALID vectors from the task spec.                                      #
# --------------------------------------------------------------------------- #
KNOWN_CPF = "11144477735"
KNOWN_CNPJ = "11222333000181"
KNOWN_SIN = "046454286"
KNOWN_VIN = "1HGBH41JXMN109186"
KNOWN_CURP = "HEGG560427MVZRRL04"

# base58 alphabet (Bitcoin/TRON/Solana): no 0, O, I, l.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def types(text: str):
    """Set of detected types after the full default engine pipeline."""
    return {f.type for f in scan(text)}


# --------------------------------------------------------------------------- #
# Sample builders — derive a VALID id from the real check-digit algorithms.    #
# --------------------------------------------------------------------------- #
def make_tfn(body8: str) -> str:
    """8 body digits -> 9-digit TFN with an appended check digit (weighted mod 11)."""
    assert len(body8) == 8 and body8.isdigit()
    for d in "0123456789":
        if validate_tfn_au(body8 + d):
            return body8 + d
    raise AssertionError("no valid TFN check digit found")  # pragma: no cover


def make_mynumber(body11: str) -> str:
    """11 body digits -> 12-digit My Number with the appended check digit."""
    assert len(body11) == 11 and body11.isdigit()
    for d in "0123456789":
        if validate_mynumber_jp(body11 + d):
            return body11 + d
    raise AssertionError("no valid My Number check digit found")  # pragma: no cover


def make_rrn(body12: str) -> str:
    """12 body digits -> 13-digit RRN with the appended check digit (mod 11)."""
    assert len(body12) == 12 and body12.isdigit()
    for d in "0123456789":
        if validate_rrn_kr(body12 + d):
            return body12 + d
    raise AssertionError("no valid RRN check digit found")  # pragma: no cover


def make_rrn_not_ogrn() -> str:
    """A valid RRN whose 13 digits are NOT also a valid Russian OGRN.

    RRN_KR (0.85) and OGRN (0.85) share the 13-digit shape and confidence; on a
    pure overlap the engine's tie-break (start, then type name) hands the span to
    OGRN. To exercise RRN_KR detection in isolation we pick a body that fails the
    OGRN checksum so only the RRN detector survives overlap resolution.
    """
    for n in range(100000):
        body12 = f"9001013{n:05d}"  # 7 + 5 = 12 digits
        cand = make_rrn(body12)
        if not validate_ogrn(cand):
            return cand
    raise AssertionError("no valid RRN that is not an OGRN")  # pragma: no cover


def flip_last(s: str) -> str:
    """Return s with its final char changed (to break a trailing check digit)."""
    last = s[-1]
    return s[:-1] + ("0" if last != "0" else "1")


def tron_address() -> str:
    """Реальный TRON-адрес (валидный base58check, версия 0x41)."""
    return "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def solana_address() -> str:
    """A 44-char base58 string in SOLANA's 32..44 length window, not T-prefixed."""
    s = (_B58 * 2)[:44]
    assert not s.startswith("T")  # so it cannot also satisfy TRON's T-prefix rule
    return s


# Build the constructed samples once.
VALID_TFN = make_tfn("12345678")
VALID_MYNUMBER = make_mynumber("12345678901")
VALID_RRN = make_rrn("900101312345")
VALID_RRN_SOLO = make_rrn_not_ogrn()
TRON_ADDR = tron_address()
SOL_ADDR = solana_address()


# --------------------------------------------------------------------------- #
# Validators — known-valid vectors and constructed-sample sanity.             #
# --------------------------------------------------------------------------- #
class TestWorldValidators(unittest.TestCase):
    def test_known_valid_vectors(self):
        self.assertTrue(validate_cpf(KNOWN_CPF))
        self.assertTrue(validate_cnpj(KNOWN_CNPJ))
        self.assertTrue(validate_sin_ca(KNOWN_SIN))
        self.assertTrue(validate_vin(KNOWN_VIN))
        self.assertTrue(validate_curp_mx(KNOWN_CURP))

    def test_constructed_apac_samples_are_valid(self):
        self.assertEqual(len(VALID_TFN), 9)
        self.assertTrue(validate_tfn_au(VALID_TFN))
        self.assertEqual(len(VALID_MYNUMBER), 12)
        self.assertTrue(validate_mynumber_jp(VALID_MYNUMBER))
        self.assertEqual(len(VALID_RRN), 13)
        self.assertTrue(validate_rrn_kr(VALID_RRN))

    def test_tampered_apac_samples_are_invalid(self):
        # Flipping the trailing check digit breaks each checksum.
        self.assertFalse(validate_tfn_au(flip_last(VALID_TFN)))
        self.assertFalse(validate_mynumber_jp(flip_last(VALID_MYNUMBER)))
        self.assertFalse(validate_rrn_kr(flip_last(VALID_RRN)))

    def test_tfn_length_gate(self):
        # validate_tfn_au only accepts 8- or 9-digit inputs.
        self.assertFalse(validate_tfn_au("1234567"))      # 7 digits
        self.assertFalse(validate_tfn_au("1234567890"))   # 10 digits

    def test_rrn_requires_thirteen_digits(self):
        self.assertFalse(validate_rrn_kr(VALID_RRN[:-1]))  # 12 digits

    def test_mynumber_requires_twelve_digits(self):
        self.assertFalse(validate_mynumber_jp(VALID_MYNUMBER + "0"))  # 13 digits


# --------------------------------------------------------------------------- #
# Australia TFN_AU — keyword-gated.                                            #
# --------------------------------------------------------------------------- #
class TestTFNDetection(unittest.TestCase):
    def test_tfn_gated_off_without_keyword(self):
        # Bare valid TFN sits at base confidence 0.4 (< default 0.7) -> dropped.
        self.assertNotIn("TFN_AU", types(f"reference {VALID_TFN}"))

    def test_tfn_detected_with_keyword(self):
        self.assertIn("TFN_AU", types(f"TFN {VALID_TFN}"))

    def test_tfn_keyword_tax_file_also_boosts(self):
        self.assertIn("TFN_AU", types(f"tax file number {VALID_TFN}"))

    def test_tfn_invalid_checksum_not_detected_even_with_keyword(self):
        bad = flip_last(VALID_TFN)
        self.assertFalse(validate_tfn_au(bad))
        self.assertNotIn("TFN_AU", types(f"TFN {bad}"))

    def test_tfn_category_and_severity(self):
        self.assertEqual(category_of("TFN_AU"), "government_id")
        self.assertEqual(severity_of("TFN_AU"), "high")


# --------------------------------------------------------------------------- #
# Japan MYNUMBER_JP — keyword-gated (Japanese keyword マイナンバー or my number).  #
# --------------------------------------------------------------------------- #
class TestMyNumberDetection(unittest.TestCase):
    def test_mynumber_gated_off_without_keyword(self):
        self.assertNotIn("MYNUMBER_JP", types(f"value {VALID_MYNUMBER}"))

    def test_mynumber_detected_with_japanese_keyword(self):
        self.assertIn("MYNUMBER_JP", types(f"マイナンバー {VALID_MYNUMBER}"))

    def test_mynumber_detected_with_ascii_keyword(self):
        self.assertIn("MYNUMBER_JP", types(f"my number {VALID_MYNUMBER}"))

    def test_mynumber_invalid_checksum_not_detected(self):
        bad = flip_last(VALID_MYNUMBER)
        self.assertFalse(validate_mynumber_jp(bad))
        self.assertNotIn("MYNUMBER_JP", types(f"マイナンバー {bad}"))

    def test_mynumber_category_and_severity(self):
        self.assertEqual(category_of("MYNUMBER_JP"), "government_id")
        self.assertEqual(severity_of("MYNUMBER_JP"), "high")


# --------------------------------------------------------------------------- #
# Korea RRN_KR — default-on (strong 13-digit mod-11 checksum).                 #
# --------------------------------------------------------------------------- #
class TestRRNDetection(unittest.TestCase):
    def test_rrn_keyword_gated(self):
        # RRN контекстно-зависим (~10% случайных 13-значных проходят mod-11):
        # без ключевого слова не маскируется, с "RRN"/주민등록번호 — да.
        self.assertTrue(validate_rrn_kr(VALID_RRN_SOLO))
        self.assertFalse(validate_ogrn(VALID_RRN_SOLO))
        self.assertNotIn("RRN_KR", types(f"число {VALID_RRN_SOLO} тут"))
        self.assertIn("RRN_KR", types(f"RRN {VALID_RRN_SOLO}"))
        self.assertIn("RRN_KR", types(f"주민등록번호 {VALID_RRN_SOLO}"))

    def test_rrn_tampered_is_not_detected(self):
        tampered = flip_last(VALID_RRN_SOLO)
        self.assertFalse(validate_rrn_kr(tampered))
        self.assertNotIn("RRN_KR", types(f"RRN {tampered}"))

    def test_rrn_overlap_with_ogrn_resolves_to_ogrn(self):
        # Documents ACTUAL behaviour: a 13-digit value valid as BOTH RRN and OGRN
        # is handed to OGRN by overlap resolution (equal confidence 0.85; the
        # tie-break orders by type name, and "OGRN" < "RRN_KR").
        self.assertTrue(validate_rrn_kr(VALID_RRN))
        self.assertTrue(validate_ogrn(VALID_RRN))
        detected = types(f"resident {VALID_RRN}")
        self.assertIn("OGRN", detected)
        self.assertNotIn("RRN_KR", detected)

    def test_rrn_category_and_severity(self):
        self.assertEqual(category_of("RRN_KR"), "government_id")
        self.assertEqual(severity_of("RRN_KR"), "high")


# --------------------------------------------------------------------------- #
# VIN (ISO 3779) — default-on (check digit at position 9).                     #
# --------------------------------------------------------------------------- #
class TestVINDetection(unittest.TestCase):
    def test_known_valid_vin_detected(self):
        self.assertIn("VIN", types(f"VIN: {KNOWN_VIN}"))

    def test_invalid_check_17char_string_is_not_a_vin(self):
        # Flip the check digit (position 8, 0-indexed) -> fails ISO 3779 check.
        bad = KNOWN_VIN[:8] + ("0" if KNOWN_VIN[8] != "0" else "1") + KNOWN_VIN[9:]
        self.assertEqual(len(bad), 17)
        self.assertFalse(validate_vin(bad))
        self.assertNotIn("VIN", types(f"vehicle {bad}"))

    def test_vin_rejects_illegal_letters_i_o_q(self):
        # I, O, Q are not permitted in a VIN; the validator (and regex) reject it.
        self.assertFalse(validate_vin("1HGBH41JXMN1O9186"))

    def test_vin_category_and_severity(self):
        self.assertEqual(category_of("VIN"), "government_id")
        self.assertEqual(severity_of("VIN"), "high")


# --------------------------------------------------------------------------- #
# TRON_ADDRESS — default-on (structural: 'T' + 33 base58).                     #
# --------------------------------------------------------------------------- #
class TestTronDetection(unittest.TestCase):
    def test_tron_address_detected_default_on(self):
        self.assertEqual(len(TRON_ADDR), 34)
        self.assertTrue(TRON_ADDR.startswith("T"))
        self.assertIn("TRON_ADDRESS", types(f"sent funds to {TRON_ADDR}"))

    def test_tron_too_short_not_detected(self):
        short = "T" + _B58[:20]  # only 21 chars total
        self.assertNotIn("TRON_ADDRESS", types(f"wallet {short}"))

    def test_tron_category_and_severity(self):
        self.assertEqual(category_of("TRON_ADDRESS"), "crypto")
        self.assertEqual(severity_of("TRON_ADDRESS"), "high")


# --------------------------------------------------------------------------- #
# SOLANA_ADDRESS — keyword-gated (solana / SOL / phantom).                     #
# --------------------------------------------------------------------------- #
class TestSolanaDetection(unittest.TestCase):
    def test_solana_gated_off_without_keyword(self):
        # 44-char base58 at base confidence 0.4 (< default 0.7) -> dropped.
        self.assertNotIn("SOLANA_ADDRESS", types(f"address {SOL_ADDR}"))

    def test_solana_detected_with_solana_keyword(self):
        self.assertIn("SOLANA_ADDRESS", types(f"my solana wallet {SOL_ADDR}"))

    def test_solana_detected_with_sol_keyword(self):
        self.assertIn("SOLANA_ADDRESS", types(f"send SOL to {SOL_ADDR}"))

    def test_solana_category_and_severity(self):
        self.assertEqual(category_of("SOLANA_ADDRESS"), "crypto")
        self.assertEqual(severity_of("SOLANA_ADDRESS"), "high")


# --------------------------------------------------------------------------- #
# Latin-America government IDs (known-valid vectors detected default-on).      #
# --------------------------------------------------------------------------- #
class TestLatamGovernmentIds(unittest.TestCase):
    def test_cpf_detected(self):
        self.assertIn("CPF_BR", types(f"CPF {KNOWN_CPF}"))

    def test_cnpj_detected(self):
        self.assertIn("CNPJ_BR", types(f"CNPJ {KNOWN_CNPJ}"))

    def test_curp_detected(self):
        self.assertIn("CURP_MX", types(f"CURP {KNOWN_CURP}"))

    def test_sin_keyword_gated(self):
        # SIN_CA is keyword-gated; with the SIN keyword the valid number surfaces.
        self.assertIn("SIN_CA", types(f"SIN {KNOWN_SIN}"))
        self.assertNotIn("SIN_CA", types(f"number {KNOWN_SIN}"))

    def test_latam_categories(self):
        for t in ("CPF_BR", "CNPJ_BR", "CURP_MX", "SIN_CA"):
            self.assertEqual(category_of(t), "government_id", t)
            self.assertEqual(severity_of(t), "high", t)


# --------------------------------------------------------------------------- #
# Block-L secrets — prefix-gated tokens.                                       #
# --------------------------------------------------------------------------- #
class TestBlockLSecrets(unittest.TestCase):
    def test_stripe_webhook_detected(self):
        secret = "whsec_" + "A1b2C3d4" * 5  # 40 body chars
        self.assertIn("STRIPE_WEBHOOK", types(f"endpoint secret {secret}"))

    def test_vault_token_detected(self):
        secret = "hvs." + "A1b2C3d4e5" * 3  # 30 body chars
        self.assertIn("VAULT_TOKEN", types(f"VAULT_TOKEN={secret}"))

    def test_doppler_token_detected(self):
        secret = "dp.st." + "a1b2c3d4e5" * 5  # 50 body chars
        self.assertIn("DOPPLER_TOKEN", types(f"config token {secret}"))

    def test_planetscale_token_detected(self):
        secret = "pscale_pw_" + "abcd1234" * 5  # 40 body chars
        self.assertIn("PLANETSCALE_TOKEN", types(f"db password {secret}"))

    def test_linear_token_detected(self):
        secret = "lin_api_" + "abcd1234ef" * 5  # 50 body chars
        self.assertIn("LINEAR_TOKEN", types(f"linear api key {secret}"))

    def test_block_l_secret_categories(self):
        for t in (
            "STRIPE_WEBHOOK",
            "VAULT_TOKEN",
            "DOPPLER_TOKEN",
            "PLANETSCALE_TOKEN",
            "LINEAR_TOKEN",
        ):
            self.assertEqual(category_of(t), "secret", t)
            self.assertEqual(severity_of(t), "critical", t)

    def test_prefix_gating_no_false_positive(self):
        # Without its literal prefix, none of the Block-L secrets fire.
        plain = "this is a perfectly ordinary sentence with no tokens at all"
        detected = types(plain)
        for t in (
            "STRIPE_WEBHOOK",
            "VAULT_TOKEN",
            "DOPPLER_TOKEN",
            "PLANETSCALE_TOKEN",
            "LINEAR_TOKEN",
        ):
            self.assertNotIn(t, detected, t)


# --------------------------------------------------------------------------- #
# Block L precision tightening — regression guard.                            #
#                                                                             #
# A single mod-11 / ISO-3779 check passes ~9% of random 13-digit / 17-char    #
# tokens, so RRN_KR and VIN are keyword-gated: a *valid* value alone must NOT #
# fire, only a value next to its keyword. TRON keeps base58check, so a 'T'+33 #
# string with a broken checksum must NOT fire.                                #
# --------------------------------------------------------------------------- #
class TestBlockLPrecisionRegression(unittest.TestCase):
    def test_valid_vin_without_keyword_is_suppressed(self):
        # KNOWN_VIN passes ISO 3779 but, with no VIN keyword nearby, must not fire.
        self.assertTrue(validate_vin(KNOWN_VIN))
        self.assertNotIn("VIN", types(f"артикул {KNOWN_VIN} на полке"))

    def test_valid_vin_with_keyword_fires(self):
        self.assertIn("VIN", types(f"номер кузова {KNOWN_VIN}"))

    def test_valid_rrn_without_keyword_is_suppressed(self):
        # 13-digit value that passes RRN mod-11 but NOT OGRN -> nothing without kw.
        rrn = _rrn_not_ogrn()
        self.assertTrue(validate_rrn_kr(rrn))
        self.assertFalse(validate_ogrn(rrn))
        self.assertEqual(types(f"заказ {rrn} оформлен"), set())

    def test_valid_rrn_with_keyword_fires(self):
        rrn = _rrn_not_ogrn()
        self.assertIn("RRN_KR", types(f"주민등록번호 {rrn}"))

    def test_tron_bad_checksum_is_rejected(self):
        # Real address with its last base58 char flipped -> checksum fails.
        good = TRON_ADDR
        bad = good[:-1] + ("X" if good[-1] != "X" else "Y")
        self.assertTrue(validate_tron(good))
        self.assertFalse(validate_tron(bad))
        self.assertNotIn("TRON_ADDRESS", types(f"на стене {bad}"))


def _rrn_not_ogrn():
    """A 13-digit RRN-valid value that is not also a valid OGRN."""
    base = 9001013100000
    for n in range(base, base + 100000):
        c = str(n)
        if validate_rrn_kr(c) and not validate_ogrn(c):
            return c
    raise AssertionError


# --------------------------------------------------------------------------- #
# redact() end-to-end — values masked, not echoed.                            #
# --------------------------------------------------------------------------- #
class TestRedactEndToEnd(unittest.TestCase):
    def test_rrn_value_masked(self):
        result = redact(f"RRN {VALID_RRN_SOLO}")
        self.assertNotIn(VALID_RRN_SOLO, result.masked_text)
        self.assertIn("RRN_KR", result.stats)

    def test_tron_value_masked(self):
        result = redact(f"sent to {TRON_ADDR}")
        self.assertNotIn(TRON_ADDR, result.masked_text)
        self.assertIn("TRON_ADDRESS", result.stats)

    def test_keyword_gated_tfn_value_masked_with_keyword(self):
        result = redact(f"TFN {VALID_TFN}")
        self.assertNotIn(VALID_TFN, result.masked_text)
        self.assertIn("TFN_AU", result.stats)


# --------------------------------------------------------------------------- #
# Catalog wiring — counts computed dynamically (never hardcoded).             #
# --------------------------------------------------------------------------- #
class TestCatalogWiring(unittest.TestCase):
    def setUp(self):
        self.catalog = build_catalog(Config())

    def test_new_types_present_and_default_state(self):
        by_type_default = {}
        for info in self.catalog:
            # default_enabled is a property of the detector definition; OR across
            # any detector sharing a type (e.g. GITHUB_TOKEN has two detectors).
            by_type_default.setdefault(info.detector.type, False)
            by_type_default[info.detector.type] |= info.default_enabled

        default_on_expected = {
            "CPF_BR", "CNPJ_BR", "RRN_KR", "CURP_MX", "VIN", "TRON_ADDRESS",
        }
        for t in default_on_expected:
            self.assertIn(t, by_type_default, t)
            self.assertTrue(by_type_default[t], f"{t} should be default-on")

        keyword_gated = {"SIN_CA", "TFN_AU", "MYNUMBER_JP", "SOLANA_ADDRESS"}
        for t in keyword_gated:
            self.assertIn(t, by_type_default, t)
        # Keyword-gated detectors are still "enabled" in the catalog (they just
        # rely on confidence boost, not on a default-off flag).
        gated_names = {"sin_ca", "tfn_au", "mynumber_jp", "solana_address"}
        gated_infos = [
            info for info in self.catalog if info.detector.name in gated_names
        ]
        self.assertEqual(len(gated_infos), len(gated_names))
        for info in gated_infos:
            self.assertTrue(info.default_enabled)
            self.assertTrue(info.enabled)

        for t in (
            "STRIPE_WEBHOOK",
            "VAULT_TOKEN",
            "DOPPLER_TOKEN",
            "PLANETSCALE_TOKEN",
            "LINEAR_TOKEN",
        ):
            self.assertIn(t, by_type_default, t)
            self.assertTrue(by_type_default[t], f"{t} should be default-on")

    def test_counts_are_self_consistent(self):
        # Computed from build_catalog — asserts internal relationships, no magic
        # numbers, so the suite stays correct as the catalog grows.
        total = len(self.catalog)
        default_on = sum(1 for info in self.catalog if info.default_enabled)
        types_count = len({info.detector.type for info in self.catalog})

        self.assertGreater(total, 0)
        self.assertLessEqual(default_on, total)
        self.assertLessEqual(types_count, total)  # types may collapse across detectors

        active = [info for info in self.catalog if info.enabled]
        # With the default Config, every default-on detector is active.
        self.assertEqual(
            sum(1 for info in self.catalog if info.default_enabled),
            sum(1 for info in active if info.default_enabled),
        )


if __name__ == "__main__":
    unittest.main()
