"""Exhaustive tests for datashield.validators_intl (Block C).

Each validator is exercised with valid, invalid, wrong-length and non-character
inputs. Where the task supplied no public known-valid vector (Aadhaar, China ID,
FR NIR), the test constructs a valid sample by recomputing the checksum with an
*independent* implementation embedded in this file, then re-confirms it against
the production validator. This guards against simply copying a hardcoded value
whose validity was never checked.

stdlib unittest only.
"""
import unittest

from datashield.validators_intl import (
    _DNI_LETTERS,  # mapping used in sanity check
    validate_aadhaar,
    validate_aba,
    validate_china_id,
    validate_codice_fiscale,
    validate_de_taxid,
    validate_dni_es,
    validate_fr_nir,
    validate_nhs,
    validate_nie_es,
    validate_pesel,
    verhoeff_check,
)

# --------------------------------------------------------------------------- #
# Independent re-implementations used only to *generate* valid samples.        #
# They are deliberately written from the published algorithm definitions, not  #
# copied from the production module, so a passing test proves the production    #
# validator agrees with an independent computation.                            #
# --------------------------------------------------------------------------- #

# Verhoeff: standard Dihedral D5 multiplication, permutation and inverse tables.
_V_MUL = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_V_PERM = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_V_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _verhoeff_checkdigit(payload: str) -> int:
    """Return the Verhoeff check digit that makes payload+digit valid."""
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _V_MUL[c][_V_PERM[(i + 1) % 8][int(ch)]]
    return _V_INV[c]


def _make_aadhaar(payload11: str) -> str:
    assert len(payload11) == 11
    return payload11 + str(_verhoeff_checkdigit(payload11))


_CHINA_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CHINA_CODES = "10X98765432"


def _make_china_id(body17: str) -> str:
    assert len(body17) == 17
    total = sum(int(body17[i]) * _CHINA_W[i] for i in range(17))
    return body17 + _CHINA_CODES[total % 11]


def _make_fr_nir(prefix13: str) -> str:
    """prefix13 is the 13-char body (may contain Corsica 2A/2B)."""
    assert len(prefix13) == 13
    numeric = prefix13.replace("2A", "19").replace("2B", "18")
    assert numeric.isdigit()
    key = 97 - (int(numeric) % 97)
    return prefix13 + str(key).zfill(2)


# --------------------------------------------------------------------------- #
# Sanity-check the generators against the production validators up front, so    #
# that a bug in a generator surfaces as its own failure rather than masking a   #
# product bug.                                                                  #
# --------------------------------------------------------------------------- #
class GeneratorSelfCheck(unittest.TestCase):
    def test_generated_samples_are_accepted(self):
        aadhaar = _make_aadhaar("23456789012")
        self.assertTrue(validate_aadhaar(aadhaar), aadhaar)
        self.assertTrue(verhoeff_check(aadhaar), aadhaar)

        china = _make_china_id("11010519491231002")
        self.assertTrue(validate_china_id(china), china)

        fr = _make_fr_nir("1850578006048")
        self.assertEqual(len(fr), 15)
        self.assertTrue(validate_fr_nir(fr), fr)


# --------------------------------------------------------------------------- #
# verhoeff_check directly                                                      #
# --------------------------------------------------------------------------- #
class VerhoeffTests(unittest.TestCase):
    def test_known_valid_vectors(self):
        # 236 with appended check digit 3 -> classic valid Verhoeff string.
        self.assertTrue(verhoeff_check("2363"))
        # 75872 with appended check digit 2.
        self.assertTrue(verhoeff_check("758722"))

    def test_invalid_vector(self):
        self.assertFalse(verhoeff_check("12345"))
        # Flip the last digit of a valid string -> invalid.
        self.assertFalse(verhoeff_check("2364"))

    def test_generated_check_digit_round_trips(self):
        # For several payloads, appending the independently computed digit
        # must produce a Verhoeff-valid string.
        for payload in ("0", "123", "84736251", "23456789012", "999999999"):
            digit = _verhoeff_checkdigit(payload)
            self.assertTrue(verhoeff_check(payload + str(digit)), payload)
            # And a wrong digit must fail (pick any digit != correct one).
            wrong = (digit + 1) % 10
            self.assertFalse(verhoeff_check(payload + str(wrong)), payload)

    def test_single_zero_is_valid(self):
        # "0" has running check 0 -> valid.
        self.assertTrue(verhoeff_check("0"))


# --------------------------------------------------------------------------- #
# Aadhaar (Verhoeff, 12 digits, first digit 2-9)                              #
# --------------------------------------------------------------------------- #
class AadhaarTests(unittest.TestCase):
    def setUp(self):
        self.valid = _make_aadhaar("23456789012")  # recomputed, re-confirmed
        self.assertTrue(validate_aadhaar(self.valid))

    def test_valid(self):
        self.assertTrue(validate_aadhaar(self.valid))

    def test_valid_with_spaces(self):
        spaced = f"{self.valid[:4]} {self.valid[4:8]} {self.valid[8:]}"
        self.assertTrue(validate_aadhaar(spaced))

    def test_rejects_first_digit_zero(self):
        # Construct a Verhoeff-valid 12-digit number that starts with 0; the
        # validator must still reject it on the leading-digit rule.
        payload = "01234567890"
        candidate = _make_aadhaar(payload)
        self.assertTrue(verhoeff_check(candidate))  # checksum is fine
        self.assertFalse(validate_aadhaar(candidate))  # but rejected anyway

    def test_rejects_first_digit_one(self):
        payload = "12345678901"
        candidate = _make_aadhaar(payload)
        self.assertTrue(verhoeff_check(candidate))
        self.assertFalse(validate_aadhaar(candidate))

    def test_invalid_checksum(self):
        bad = self.valid[:-1] + str((int(self.valid[-1]) + 1) % 10)
        self.assertFalse(validate_aadhaar(bad))

    def test_wrong_length(self):
        self.assertFalse(validate_aadhaar("23456789"))
        self.assertFalse(validate_aadhaar(self.valid + "0"))

    def test_non_char(self):
        self.assertFalse(validate_aadhaar("abcdabcdabcd"))
        self.assertFalse(validate_aadhaar(""))


# --------------------------------------------------------------------------- #
# NHS (mod-11, 10 digits, check 10 -> invalid)                                #
# --------------------------------------------------------------------------- #
class NhsTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_nhs("9434765919"))

    def test_valid_with_spaces(self):
        self.assertTrue(validate_nhs("943 476 5919"))

    def test_invalid_check_digit(self):
        self.assertFalse(validate_nhs("9434765910"))

    def test_check_equals_ten_is_rejected(self):
        # Independently search a 9-digit prefix whose weighted total %11 == 1,
        # which forces the computed check digit to 10 -> always invalid.
        candidate = None
        for n in range(0, 200):
            s = str(n).zfill(9)
            total = sum(int(s[i]) * (10 - i) for i in range(9))
            if total % 11 == 1:
                candidate = s + "0"
                break
        self.assertIsNotNone(candidate)
        self.assertFalse(validate_nhs(candidate))

    def test_wrong_length(self):
        self.assertFalse(validate_nhs("943476591"))
        self.assertFalse(validate_nhs("94347659190"))

    def test_non_char_stripped(self):
        # Non-digits are stripped, so a dashed valid number stays valid.
        self.assertTrue(validate_nhs("943-476-5919"))
        # All-letters -> length 0 -> invalid.
        self.assertFalse(validate_nhs("abcdefghij"))


# --------------------------------------------------------------------------- #
# PESEL (weighted, 11 digits)                                                  #
# --------------------------------------------------------------------------- #
class PeselTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_pesel("44051401359"))

    def test_invalid_check(self):
        self.assertFalse(validate_pesel("44051401358"))

    def test_wrong_length(self):
        self.assertFalse(validate_pesel("4405140135"))
        self.assertFalse(validate_pesel("440514013590"))

    def test_non_char(self):
        self.assertFalse(validate_pesel("abcdefghijk"))
        # Dashes stripped -> the digits still validate.
        self.assertTrue(validate_pesel("44-05-14-013-59"))


# --------------------------------------------------------------------------- #
# China ID (mod-11, 18 chars, check in 0-9 or X)                              #
# --------------------------------------------------------------------------- #
class ChinaIdTests(unittest.TestCase):
    def setUp(self):
        self.valid = _make_china_id("11010519491231002")  # check digit X here
        self.assertTrue(validate_china_id(self.valid))

    def test_valid(self):
        self.assertTrue(validate_china_id(self.valid))

    def test_valid_lowercase_x_check(self):
        # If the check digit is X, lowercase x is uppercased by the validator.
        if self.valid[-1] == "X":
            self.assertTrue(validate_china_id(self.valid[:-1] + "x"))

    def test_numeric_check_digit_sample(self):
        # Construct a body whose check digit is numeric, validate it.
        numeric_sample = _make_china_id("11010519491231003")
        self.assertTrue(validate_china_id(numeric_sample))

    def test_invalid_check(self):
        last = self.valid[-1]
        wrong = "0" if last != "0" else "1"
        self.assertFalse(validate_china_id(self.valid[:-1] + wrong))

    def test_wrong_length(self):
        self.assertFalse(validate_china_id(self.valid[:-1]))  # 17 chars
        self.assertFalse(validate_china_id(self.valid + "0"))  # 19 chars

    def test_non_digit_body(self):
        # First 17 must be digits; inject a letter into the body.
        bad = "A" + self.valid[1:]
        self.assertFalse(validate_china_id(bad))


# --------------------------------------------------------------------------- #
# ABA routing (weighted 3-7-1, 9 digits)                                       #
# --------------------------------------------------------------------------- #
class AbaTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_aba("021000021"))

    def test_all_zeros_passes_checksum(self):
        # Documenting actual behavior: 000000000 satisfies the weighted sum.
        self.assertTrue(validate_aba("000000000"))

    def test_invalid_check(self):
        self.assertFalse(validate_aba("021000022"))

    def test_wrong_length(self):
        self.assertFalse(validate_aba("02100002"))
        self.assertFalse(validate_aba("0210000210"))

    def test_non_char(self):
        self.assertFalse(validate_aba("abcdefghi"))
        # Dashes stripped -> digits still validate.
        self.assertTrue(validate_aba("0210-0002-1"))


# --------------------------------------------------------------------------- #
# Spain DNI (number % 23 -> control letter)                                    #
# --------------------------------------------------------------------------- #
class DniEsTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_dni_es("12345678Z"))

    def test_lowercase_accepted(self):
        self.assertTrue(validate_dni_es("12345678z"))

    def test_all_letter_mapping_round_trips(self):
        # For every remainder 0..22 the validator must accept the number paired
        # with _DNI_LETTERS[remainder] and reject any other letter.
        self.assertEqual(len(_DNI_LETTERS), 23)
        for r in range(23):
            num = str(r).zfill(8)
            correct = _DNI_LETTERS[int(num) % 23]
            self.assertTrue(validate_dni_es(num + correct), num)
            wrong = _DNI_LETTERS[(r + 1) % 23]
            self.assertFalse(validate_dni_es(num + wrong), num)

    def test_wrong_letter(self):
        self.assertFalse(validate_dni_es("12345678A"))

    def test_wrong_length(self):
        self.assertFalse(validate_dni_es("1234567Z"))  # 7 digits
        self.assertFalse(validate_dni_es("123456789Z"))  # 9 digits

    def test_non_char(self):
        self.assertFalse(validate_dni_es("1234567XY"))  # two trailing letters
        self.assertFalse(validate_dni_es("ABCDEFGHZ"))


# --------------------------------------------------------------------------- #
# Spain NIE (X/Y/Z prefix -> 0/1/2, then DNI rule)                            #
# --------------------------------------------------------------------------- #
class NieEsTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_nie_es("X1234567L"))

    def test_all_prefixes_map_correctly(self):
        for prefix, digit in (("X", "0"), ("Y", "1"), ("Z", "2")):
            value = int(digit + "1234567")
            letter = _DNI_LETTERS[value % 23]
            self.assertTrue(validate_nie_es(prefix + "1234567" + letter), prefix)

    def test_lowercase_accepted(self):
        self.assertTrue(validate_nie_es("x1234567l"))

    def test_wrong_letter(self):
        self.assertFalse(validate_nie_es("X1234567A"))

    def test_bad_prefix(self):
        self.assertFalse(validate_nie_es("A1234567L"))

    def test_wrong_length(self):
        self.assertFalse(validate_nie_es("Z1234567"))  # missing control letter
        self.assertFalse(validate_nie_es("X12345678L"))  # 8 digits

    def test_non_char(self):
        self.assertFalse(validate_nie_es("XABCDEFGL"))


# --------------------------------------------------------------------------- #
# Italy Codice Fiscale (odd/even tables -> control letter)                     #
# --------------------------------------------------------------------------- #
class CodiceFiscaleTests(unittest.TestCase):
    def test_known_valid_vectors(self):
        # Two independent known-valid CFs exercise both odd and even tables
        # across many distinct letters/digits.
        self.assertTrue(validate_codice_fiscale("RSSMRA85T10A562S"))
        self.assertTrue(validate_codice_fiscale("MRTMTT25D09F205Z"))

    def test_lowercase_accepted(self):
        self.assertTrue(validate_codice_fiscale("rssmra85t10a562s"))

    def test_invalid_control_letter(self):
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562T"))
        self.assertFalse(validate_codice_fiscale("MRTMTT25D09F205A"))

    def test_wrong_length(self):
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562"))  # 15
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562SS"))  # 17

    def test_non_char(self):
        # Non-alphanumeric breaks the [A-Z0-9]{16} structural gate.
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562-"))
        self.assertFalse(validate_codice_fiscale("RSSMRA85T10A562!"))

    def test_odd_even_position_sensitivity(self):
        # Swapping two adjacent characters changes the odd/even weighting and
        # must (for this vector) break the checksum.
        cf = "RSSMRA85T10A562S"
        swapped = cf[1] + cf[0] + cf[2:]  # swap positions 0 and 1
        self.assertFalse(validate_codice_fiscale(swapped))


# --------------------------------------------------------------------------- #
# Germany Steuer-ID (ISO 7064 MOD 11,10, 11 digits, no leading zero)           #
# --------------------------------------------------------------------------- #
class DeTaxIdTests(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(validate_de_taxid("86095742719"))

    def test_invalid_check(self):
        self.assertFalse(validate_de_taxid("86095742710"))

    def test_rejects_leading_zero(self):
        self.assertFalse(validate_de_taxid("06095742719"))

    def test_wrong_length(self):
        self.assertFalse(validate_de_taxid("8609574271"))  # 10
        self.assertFalse(validate_de_taxid("860957427190"))  # 12

    def test_non_char(self):
        self.assertFalse(validate_de_taxid("abcdefghijk"))
        # Spaces stripped -> the digits still validate.
        self.assertTrue(validate_de_taxid("86 095 742 719"))


# --------------------------------------------------------------------------- #
# France NIR (mod-97, 15 chars, Corsica 2A/2B)                                #
# --------------------------------------------------------------------------- #
class FrNirTests(unittest.TestCase):
    def setUp(self):
        self.valid = _make_fr_nir("1850578006048")  # recomputed, re-confirmed
        self.assertTrue(validate_fr_nir(self.valid))

    def test_valid(self):
        self.assertTrue(validate_fr_nir(self.valid))

    def test_valid_with_spaces(self):
        v = self.valid
        spaced = f"{v[0]} {v[1:3]} {v[3:5]} {v[5:7]} {v[7:10]} {v[10:13]} {v[13:]}"
        self.assertTrue(validate_fr_nir(spaced))

    def test_corsica_2a(self):
        sample = _make_fr_nir("1850572A04830")
        self.assertTrue(validate_fr_nir(sample), sample)

    def test_corsica_2b(self):
        sample = _make_fr_nir("1850572B04830")
        self.assertTrue(validate_fr_nir(sample), sample)

    def test_invalid_key(self):
        body = self.valid[:13]
        key = int(self.valid[13:])
        bad_key = str((key % 97) + 1).zfill(2)
        self.assertFalse(validate_fr_nir(body + bad_key))

    def test_wrong_length(self):
        self.assertFalse(validate_fr_nir(self.valid[:-1]))  # 14
        self.assertFalse(validate_fr_nir(self.valid + "0"))  # 16

    def test_non_char_in_body(self):
        # A stray non-2A/2B letter in the body makes the numeric body invalid.
        self.assertFalse(validate_fr_nir("18505G8006048" + self.valid[13:]))


if __name__ == "__main__":
    unittest.main()
