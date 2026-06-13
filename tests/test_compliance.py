"""Tests for datashield.compliance: REGULATIONS / regulations_for / classify.

Asserts actual behavior of the live compliance mapping against the live
taxonomy (category_of) so the two stay in sync. Block H: maps detected data
types to regulatory regimes (GDPR / HIPAA / PCI-DSS / CCPA) by taxonomy
category. Secrets map to no regulation; PCI-DSS covers only 'financial'.
"""
from __future__ import annotations

import unittest

from datashield import compliance
from datashield.compliance import REGULATIONS, classify, regulations_for
from datashield.taxonomy import _BY_CATEGORY, category_of


class TestRegulationsMapping(unittest.TestCase):
    """The static REGULATIONS dict: keys and their category value-sets."""

    def test_exactly_four_regulations(self):
        self.assertEqual(
            sorted(REGULATIONS.keys()), ["CCPA", "GDPR", "HIPAA", "PCI-DSS"]
        )

    def test_values_are_sets_of_known_categories(self):
        known = set(_BY_CATEGORY)
        for reg, cats in REGULATIONS.items():
            self.assertIsInstance(cats, set, reg)
            self.assertTrue(cats, "%s has empty category set" % reg)
            self.assertLessEqual(
                cats, known, "%s references unknown category" % reg
            )

    def test_pci_dss_covers_only_financial(self):
        # PCI-DSS is narrow: it covers exactly the 'financial' category.
        self.assertEqual(REGULATIONS["PCI-DSS"], {"financial"})

    def test_gdpr_value_set(self):
        self.assertEqual(
            REGULATIONS["GDPR"],
            {
                "contact",
                "person",
                "government_id",
                "financial",
                "health",
                "network",
                "crypto",
            },
        )

    def test_hipaa_value_set(self):
        self.assertEqual(
            REGULATIONS["HIPAA"],
            {"health", "person", "contact", "government_id", "financial", "network"},
        )

    def test_ccpa_value_set(self):
        self.assertEqual(
            REGULATIONS["CCPA"],
            {"contact", "person", "government_id", "financial", "network"},
        )

    def test_secret_category_in_no_regulation(self):
        # Secrets (API keys, tokens, passwords) map to no regulatory regime.
        for reg, cats in REGULATIONS.items():
            self.assertNotIn("secret", cats, reg)


class TestRegulationsFor(unittest.TestCase):
    """regulations_for(type) -> sorted list of regs covering the type's category."""

    def test_email_contact_pii(self):
        # EMAIL is 'contact' -> broad PII regs but NOT the financial-only PCI-DSS.
        self.assertEqual(category_of("EMAIL"), "contact")
        self.assertEqual(regulations_for("EMAIL"), ["CCPA", "GDPR", "HIPAA"])

    def test_credit_card_adds_pci_dss(self):
        # CREDIT_CARD is 'financial' -> all four including PCI-DSS.
        self.assertEqual(category_of("CREDIT_CARD"), "financial")
        self.assertEqual(
            regulations_for("CREDIT_CARD"), ["CCPA", "GDPR", "HIPAA", "PCI-DSS"]
        )

    def test_network_ip_excludes_pci_dss(self):
        # IP is 'network' -> broad PII regs but NOT PCI-DSS.
        self.assertEqual(category_of("IP"), "network")
        self.assertEqual(regulations_for("IP"), ["CCPA", "GDPR", "HIPAA"])

    def test_secret_type_maps_to_no_regulation(self):
        # A secret type (e.g. AWS key) is in no regulatory regime -> [].
        self.assertEqual(category_of("AWS_ACCESS_KEY"), "secret")
        self.assertEqual(regulations_for("AWS_ACCESS_KEY"), [])
        self.assertEqual(regulations_for("JWT"), [])
        self.assertEqual(regulations_for("PASSWORD"), [])

    def test_unknown_type_maps_to_no_regulation(self):
        # An unrecognized type falls into 'other' -> [].
        self.assertEqual(category_of("NOT_A_REAL_TYPE"), "other")
        self.assertEqual(regulations_for("NOT_A_REAL_TYPE"), [])

    def test_crypto_type_only_gdpr(self):
        # crypto category is covered only by GDPR.
        self.assertEqual(category_of("ETH_ADDRESS"), "crypto")
        self.assertEqual(regulations_for("ETH_ADDRESS"), ["GDPR"])

    def test_health_type_three_regs(self):
        # health category -> GDPR, HIPAA, CCPA? CCPA does NOT list 'health'.
        self.assertEqual(category_of("OMS_POLICY"), "health")
        self.assertEqual(regulations_for("OMS_POLICY"), ["GDPR", "HIPAA"])

    def test_result_is_sorted(self):
        # Output is alphabetically sorted regardless of dict insertion order.
        regs = regulations_for("CREDIT_CARD")
        self.assertEqual(regs, sorted(regs))


class TestRegulationsForInvariants(unittest.TestCase):
    """Cross-checks against the live taxonomy."""

    def _all_taxonomy_types(self):
        result = set()
        for types in _BY_CATEGORY.values():
            result |= types
        return result

    def test_only_financial_types_map_to_pci_dss(self):
        # Every type whose regs include PCI-DSS must be a 'financial' type,
        # and every 'financial' type must include PCI-DSS.
        financial = set(_BY_CATEGORY["financial"])
        pci_types = {
            t for t in self._all_taxonomy_types() if "PCI-DSS" in regulations_for(t)
        }
        self.assertEqual(pci_types, financial)

    def test_secret_types_never_regulated(self):
        for t in _BY_CATEGORY["secret"]:
            self.assertEqual(regulations_for(t), [], t)

    def test_each_regulation_reachable_from_some_type(self):
        # Sanity: each of the four regs is produced by at least one real type.
        produced = set()
        for t in self._all_taxonomy_types():
            produced.update(regulations_for(t))
        self.assertEqual(produced, set(REGULATIONS))


class TestClassify(unittest.TestCase):
    """classify(types) -> {reg: sorted [types]}, deduped, sorted by reg."""

    def test_empty_input(self):
        self.assertEqual(classify([]), {})

    def test_empty_set_input(self):
        self.assertEqual(classify(set()), {})

    def test_multi_type_set(self):
        result = classify(["EMAIL", "CREDIT_CARD", "IP", "AWS_ACCESS_KEY"])
        self.assertEqual(
            result,
            {
                "CCPA": ["CREDIT_CARD", "EMAIL", "IP"],
                "GDPR": ["CREDIT_CARD", "EMAIL", "IP"],
                "HIPAA": ["CREDIT_CARD", "EMAIL", "IP"],
                "PCI-DSS": ["CREDIT_CARD"],
            },
        )

    def test_secret_contributes_nothing(self):
        # The secret type is silently dropped from every bucket.
        result = classify(["EMAIL", "AWS_ACCESS_KEY"])
        for types in result.values():
            self.assertNotIn("AWS_ACCESS_KEY", types)
        self.assertEqual(
            result,
            {
                "CCPA": ["EMAIL"],
                "GDPR": ["EMAIL"],
                "HIPAA": ["EMAIL"],
            },
        )

    def test_unknown_type_contributes_nothing(self):
        result = classify(["UNKNOWN_FOO", "AWS_ACCESS_KEY"])
        self.assertEqual(result, {})

    def test_duplicates_deduped(self):
        result = classify(["EMAIL", "EMAIL", "CREDIT_CARD", "CREDIT_CARD"])
        self.assertEqual(
            result,
            {
                "CCPA": ["CREDIT_CARD", "EMAIL"],
                "GDPR": ["CREDIT_CARD", "EMAIL"],
                "HIPAA": ["CREDIT_CARD", "EMAIL"],
                "PCI-DSS": ["CREDIT_CARD"],
            },
        )

    def test_type_lists_are_sorted(self):
        result = classify(["IP", "EMAIL", "CREDIT_CARD"])
        for types in result.values():
            self.assertEqual(types, sorted(types))

    def test_regulation_keys_are_sorted(self):
        result = classify(["CREDIT_CARD", "EMAIL", "IP"])
        self.assertEqual(list(result.keys()), sorted(result.keys()))

    def test_pci_dss_bucket_only_financial(self):
        # Only financial types ever land in the PCI-DSS bucket.
        result = classify(["CREDIT_CARD", "IBAN", "EMAIL", "IP", "ETH_ADDRESS"])
        self.assertEqual(result["PCI-DSS"], ["CREDIT_CARD", "IBAN"])
        for t in result["PCI-DSS"]:
            self.assertEqual(category_of(t), "financial")

    def test_accepts_generator_iterable(self):
        # Iterable, not just list/set: a one-shot generator must work.
        result = classify(t for t in ("EMAIL", "CREDIT_CARD"))
        self.assertEqual(
            result,
            {
                "CCPA": ["CREDIT_CARD", "EMAIL"],
                "GDPR": ["CREDIT_CARD", "EMAIL"],
                "HIPAA": ["CREDIT_CARD", "EMAIL"],
                "PCI-DSS": ["CREDIT_CARD"],
            },
        )

    def test_consistent_with_regulations_for(self):
        # classify is just the inverse-index of regulations_for over the input.
        types = ["EMAIL", "CREDIT_CARD", "IP", "OMS_POLICY"]
        result = classify(types)
        for t in types:
            for reg in regulations_for(t):
                self.assertIn(t, result[reg])


class TestReportComplianceIntegration(unittest.TestCase):
    """RedactionResult.report() exposes a top-level 'compliance' key = classify(...)."""

    def test_report_has_compliance_classify_of_found_types(self):
        from datashield import redact

        text = (
            "email a@b.com card 4111 1111 1111 1111 ip 10.0.0.1 "
            "token sk-ant-api03-" + "x" * 95
        )
        result = redact(text)
        report = result.report(salt=b"fixedsalt")
        self.assertIn("compliance", report)
        found = {f.type for f in result.findings}
        self.assertEqual(report["compliance"], classify(found))

    def test_report_compliance_drops_detected_secret(self):
        from datashield import redact

        text = "email a@b.com token sk-ant-api03-" + "x" * 95
        result = redact(text)
        found = {f.type for f in result.findings}
        # An Anthropic key (secret) is among findings...
        self.assertTrue(any(category_of(t) == "secret" for t in found))
        # ...but it does not appear in any compliance bucket.
        report = result.report(salt=b"fixedsalt")
        for types in report["compliance"].values():
            for t in types:
                self.assertNotEqual(category_of(t), "secret")


class TestModulePublicSurface(unittest.TestCase):
    def test_dunder_all(self):
        self.assertEqual(
            sorted(compliance.__all__),
            ["REGULATIONS", "classify", "regulations_for"],
        )


if __name__ == "__main__":
    unittest.main()
