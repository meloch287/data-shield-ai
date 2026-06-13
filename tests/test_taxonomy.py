"""Tests for datashield.taxonomy: category_of / severity_of / types_in_categories.

Asserts actual behavior of the live taxonomy against the live detector catalog
(build_catalog) so the two stay in sync.
"""
from __future__ import annotations

import unittest

from datashield import taxonomy
from datashield.config import Config
from datashield.detectors.registry import build_catalog


def _catalog_types():
    """Every detector type present in the live catalog (default config)."""
    return {info.detector.type for info in build_catalog(Config())}


class TestCategoryOf(unittest.TestCase):
    def test_representative_type_per_category(self):
        # One representative type per category, matching the live mapping.
        expected = {
            "EMAIL": "contact",
            "PERSON": "person",
            "INN": "government_id",
            "CREDIT_CARD": "financial",
            "OMS_POLICY": "health",
            "ETH_ADDRESS": "crypto",
            "IP": "network",
            "JWT": "secret",
        }
        for type_name, category in expected.items():
            self.assertEqual(taxonomy.category_of(type_name), category)

    def test_unknown_type_falls_back_to_other(self):
        self.assertEqual(taxonomy.category_of("TOTALLY_FAKE_TYPE"), "other")

    def test_every_declared_category_is_non_empty(self):
        for category in taxonomy.CATEGORIES:
            self.assertTrue(
                taxonomy.types_in_categories([category]),
                f"category {category!r} should declare at least one type",
            )


class TestSeverityOf(unittest.TestCase):
    def test_credit_card_is_critical(self):
        # CREDIT_CARD lives in 'financial' (high) but is overridden to critical.
        self.assertEqual(taxonomy.category_of("CREDIT_CARD"), "financial")
        self.assertEqual(taxonomy.severity_of("CREDIT_CARD"), "critical")

    def test_secret_is_critical(self):
        self.assertEqual(taxonomy.severity_of("AWS_SECRET_KEY"), "critical")
        self.assertEqual(taxonomy.severity_of("OPENAI_KEY"), "critical")

    def test_ip_is_low(self):
        self.assertEqual(taxonomy.category_of("IP"), "network")
        self.assertEqual(taxonomy.severity_of("IP"), "low")

    def test_category_severity_mapping(self):
        # Representative type per category -> expected severity.
        expected = {
            "EMAIL": "medium",        # contact
            "PERSON": "medium",       # person
            "INN": "high",            # government_id
            "IBAN": "high",           # financial (non-overridden)
            "OMS_POLICY": "high",     # health
            "BTC_ADDRESS": "high",    # crypto
            "MAC": "low",             # network
            "JWT": "critical",        # secret
        }
        for type_name, severity in expected.items():
            self.assertEqual(taxonomy.severity_of(type_name), severity)

    def test_unknown_type_severity_defaults_to_medium(self):
        self.assertEqual(taxonomy.severity_of("TOTALLY_FAKE_TYPE"), "medium")


class TestSeverityOrder(unittest.TestCase):
    def test_levels_and_values(self):
        self.assertEqual(
            taxonomy.SEVERITY_ORDER,
            {"low": 0, "medium": 1, "high": 2, "critical": 3},
        )

    def test_strictly_increasing(self):
        ordered = ["low", "medium", "high", "critical"]
        values = [taxonomy.SEVERITY_ORDER[level] for level in ordered]
        for lower, higher in zip(values, values[1:]):
            self.assertLess(lower, higher)


class TestTypesInCategories(unittest.TestCase):
    def test_union_correctness(self):
        financial = taxonomy.types_in_categories(["financial"])
        crypto = taxonomy.types_in_categories(["crypto"])
        union = taxonomy.types_in_categories(["financial", "crypto"])
        self.assertEqual(union, financial | crypto)
        # Non-empty and disjoint sources, so the union is strictly larger.
        self.assertTrue(financial)
        self.assertTrue(crypto)
        self.assertGreater(len(union), len(financial))

    def test_unknown_category_yields_empty(self):
        self.assertEqual(taxonomy.types_in_categories(["does-not-exist"]), set())

    def test_unknown_category_does_not_pollute_known_union(self):
        known = taxonomy.types_in_categories(["secret"])
        mixed = taxonomy.types_in_categories(["secret", "does-not-exist"])
        self.assertEqual(known, mixed)

    def test_empty_iterable_yields_empty(self):
        self.assertEqual(taxonomy.types_in_categories([]), set())

    def test_returns_a_fresh_set(self):
        # Mutating the result must not corrupt the internal category map.
        first = taxonomy.types_in_categories(["network"])
        first.add("SOMETHING_ELSE")
        second = taxonomy.types_in_categories(["network"])
        self.assertNotIn("SOMETHING_ELSE", second)


class TestLiveCatalogCoverage(unittest.TestCase):
    def test_catalog_is_non_empty(self):
        self.assertTrue(_catalog_types())

    def test_every_catalog_type_has_valid_category_and_severity(self):
        valid_categories = set(taxonomy.CATEGORIES) | {"other"}
        for type_name in _catalog_types():
            category = taxonomy.category_of(type_name)
            self.assertIn(
                category,
                valid_categories,
                f"{type_name} mapped to unexpected category {category!r}",
            )
            self.assertTrue(category, f"{type_name} mapped to empty category")
            severity = taxonomy.severity_of(type_name)
            self.assertIn(
                severity,
                taxonomy.SEVERITY_ORDER,
                f"{type_name} severity {severity!r} not in SEVERITY_ORDER",
            )

    def test_no_catalog_type_falls_through_to_other(self):
        # With the default config every shipped detector type is explicitly
        # categorized; none should land in the 'other' fallback.
        others = sorted(
            t for t in _catalog_types() if taxonomy.category_of(t) == "other"
        )
        self.assertEqual(others, [])


if __name__ == "__main__":
    unittest.main()
