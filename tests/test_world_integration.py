"""Интеграционные тесты Блока L: каталог + таксономия + compliance для новых типов.

Проверяют ФАКТИЧЕСКОЕ поведение (прочитаны реальные исходники):

* build_catalog(Config()) включает все новые мировые детекторы (BR/CA/AU/JP/KR/MX,
  VIN, TRON/SOLANA) и новые секреты (Stripe webhook, Vault, Doppler, PlanetScale,
  Linear) — присутствие проверяется по имени детектора, счётчики вычисляются
  динамически из самого каталога (НЕ захардкожены).
* Каждый новый тип маппится в категорию (национальные ID и VIN → government_id,
  TRON/SOLANA → crypto, новые токены → secret) и в критичность из SEVERITY_ORDER.
* report()["compliance"] группирует документ с CPF+CNPJ под GDPR/HIPAA/CCPA.
* Новые типы появляются в выводе `datashield types`.

Контрольные суммы валидаторов используются только для построения корректных
сэмплов (TFN/MyNumber/RRN считаются алгоритмом, не захардкожены как «магия»).
Только stdlib unittest.
"""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from datashield import redact, scan
from datashield.cli import main
from datashield.compliance import classify, regulations_for
from datashield.config import Config
from datashield.detectors.registry import build_catalog
from datashield.taxonomy import (
    SEVERITY_ORDER,
    category_of,
    severity_of,
)
from datashield.validators_world import (
    validate_cnpj,
    validate_cpf,
    validate_curp_mx,
    validate_mynumber_jp,
    validate_rrn_kr,
    validate_sin_ca,
    validate_tfn_au,
    validate_vin,
)

# --- KNOWN-VALID сэмплы из задания (подтверждены против реальных валидаторов) ---
CPF = "11144477735"
CNPJ = "11222333000181"
SIN = "046454286"
VIN = "1HGBH41JXMN109186"
CURP = "HEGG560427MVZRRL04"


def _build_valid(validator, candidates):
    """Вернуть первый сэмпл из candidates, который проходит validator."""
    for cand in candidates:
        if validator(cand):
            return cand
    raise AssertionError("не удалось построить валидный сэмпл")


def _valid_tfn():
    # 8–9 цифр, взвешенная сумма mod 11 == 0; перебираем последнюю цифру 9-значного.
    return _build_valid(validate_tfn_au, [f"12345678{d}" for d in range(10)])


def _valid_mynumber():
    # 12 цифр; контрольная по первым 11.
    return _build_valid(validate_mynumber_jp, [f"12345678901{d}" for d in range(10)])


def _valid_rrn():
    # 13 цифр; контрольная по первым 12.
    return _build_valid(validate_rrn_kr, [f"901011023451{d}" for d in range(10)])


# Новые типы Блока L, сгруппированные по ожидаемой категории.
GOV_ID_TYPES = [
    "CPF_BR", "CNPJ_BR", "SIN_CA", "TFN_AU", "MYNUMBER_JP", "RRN_KR",
    "CURP_MX", "VIN",
]
CRYPTO_TYPES = ["TRON_ADDRESS", "SOLANA_ADDRESS"]
SECRET_TYPES = [
    "STRIPE_WEBHOOK", "VAULT_TOKEN", "DOPPLER_TOKEN", "PLANETSCALE_TOKEN",
    "LINEAR_TOKEN",
]
ALL_NEW_TYPES = GOV_ID_TYPES + CRYPTO_TYPES + SECRET_TYPES

# Имена детекторов из реальных исходников (world_ids.py, secrets.py).
NEW_DETECTOR_NAMES = [
    "cpf_br", "cnpj_br", "rrn_kr", "curp_mx", "vin", "tron_address",
    "sin_ca", "tfn_au", "mynumber_jp", "solana_address",
    "stripe_webhook", "hashicorp_vault", "doppler_token",
    "planetscale_token", "linear_token",
]


class CatalogIncludesNewDetectors(unittest.TestCase):
    def setUp(self):
        self.catalog = build_catalog(Config())
        self.by_name = {info.detector.name: info for info in self.catalog}
        self.types = {info.detector.type for info in self.catalog}

    def test_all_new_detector_names_present(self):
        for name in NEW_DETECTOR_NAMES:
            self.assertIn(name, self.by_name, f"детектор {name} отсутствует в каталоге")

    def test_all_new_types_present(self):
        for t in ALL_NEW_TYPES:
            self.assertIn(t, self.types, f"тип {t} отсутствует в каталоге")

    def test_default_on_new_types_are_enabled_by_default(self):
        # CPF/CNPJ/RRN/CURP/VIN/TRON — сильная валидация → по умолчанию вкл.
        for name in ("cpf_br", "cnpj_br", "rrn_kr", "curp_mx", "vin", "tron_address"):
            self.assertTrue(
                self.by_name[name].default_enabled,
                f"{name} должен быть включён по умолчанию",
            )
            self.assertTrue(self.by_name[name].enabled)

    def test_keyword_gated_new_detectors_still_default_on(self):
        # SIN/TFN/MyNumber/Solana форматно-общие, но в каталоге default_enabled=True
        # (контекст влияет на уверенность находки, а не на включённость детектора).
        for name in ("sin_ca", "tfn_au", "mynumber_jp", "solana_address"):
            self.assertTrue(self.by_name[name].default_enabled)

    def test_new_secret_detectors_default_on(self):
        for name in ("stripe_webhook", "hashicorp_vault", "doppler_token",
                     "planetscale_token", "linear_token"):
            self.assertTrue(self.by_name[name].default_enabled)
            self.assertTrue(self.by_name[name].enabled)

    def test_catalog_counts_are_self_consistent(self):
        # Счётчики ВЫЧИСЛЯЮТСЯ из каталога, не захардкожены.
        total = len(self.catalog)
        default_on = sum(1 for i in self.catalog if i.default_enabled)
        enabled = sum(1 for i in self.catalog if i.enabled)
        n_types = len(self.types)
        # default-on не больше общего; типов не больше детекторов (типы повторяются).
        self.assertLessEqual(default_on, total)
        self.assertLessEqual(n_types, total)
        self.assertGreater(default_on, 0)
        # Без конфиг-оверрайдов enabled == default_on.
        self.assertEqual(enabled, default_on)
        # Новые типы вносят вклад в счётчики: их присутствие повышает n_types
        # относительно каталога без них.
        self.assertTrue(set(ALL_NEW_TYPES).issubset(self.types))


class TaxonomyMappingForNewTypes(unittest.TestCase):
    def test_government_id_types_map_to_government_id(self):
        for t in GOV_ID_TYPES:
            self.assertEqual(
                category_of(t), "government_id",
                f"{t} должен относиться к government_id",
            )

    def test_crypto_types_map_to_crypto(self):
        for t in CRYPTO_TYPES:
            self.assertEqual(category_of(t), "crypto", f"{t} должен быть crypto")

    def test_secret_types_map_to_secret(self):
        for t in SECRET_TYPES:
            self.assertEqual(category_of(t), "secret", f"{t} должен быть secret")

    def test_every_new_type_has_severity_in_order(self):
        for t in ALL_NEW_TYPES:
            sev = severity_of(t)
            self.assertIn(
                sev, SEVERITY_ORDER,
                f"критичность {sev!r} типа {t} вне SEVERITY_ORDER",
            )

    def test_government_id_and_crypto_are_high_secrets_critical(self):
        for t in GOV_ID_TYPES + CRYPTO_TYPES:
            self.assertEqual(severity_of(t), "high", t)
        for t in SECRET_TYPES:
            self.assertEqual(severity_of(t), "critical", t)


class ValidatorsAcceptKnownSamples(unittest.TestCase):
    """Сэмплы из задания принимаются реальными валидаторами (страховка перед
    интеграционными проверками обнаружения)."""

    def test_known_valid_samples(self):
        self.assertTrue(validate_cpf(CPF))
        self.assertTrue(validate_cnpj(CNPJ))
        self.assertTrue(validate_sin_ca(SIN))
        self.assertTrue(validate_vin(VIN))
        self.assertTrue(validate_curp_mx(CURP))

    def test_constructed_samples_valid(self):
        self.assertTrue(validate_tfn_au(_valid_tfn()))
        self.assertTrue(validate_mynumber_jp(_valid_mynumber()))
        self.assertTrue(validate_rrn_kr(_valid_rrn()))


class DetectionEndToEnd(unittest.TestCase):
    """Новые типы реально находятся движком через публичный scan()."""

    def test_default_on_world_ids_detected_without_keyword(self):
        text = f"CPF {CPF}, CNPJ {CNPJ}, VIN {VIN}, CURP {CURP}, RRN {_valid_rrn()}"
        found = {f.type for f in scan(text)}
        for t in ("CPF_BR", "CNPJ_BR", "VIN", "CURP_MX", "RRN_KR"):
            self.assertIn(t, found, f"{t} не обнаружен в тексте")

    def test_keyword_gated_sin_needs_keyword(self):
        # С ключевым словом находка проходит порог уверенности по умолчанию (0.7).
        with_kw = {f.type for f in scan(f"SIN {SIN}")}
        self.assertIn("SIN_CA", with_kw)
        # Без ключа уверенность 0.4 < 0.7 → SIN_CA отсеивается.
        without_kw = {f.type for f in scan(SIN)}
        self.assertNotIn("SIN_CA", without_kw)

    def test_new_secret_tokens_detected(self):
        samples = {
            "STRIPE_WEBHOOK": "whsec_" + "a" * 40,
            "VAULT_TOKEN": "hvs." + "B" * 30,
            "DOPPLER_TOKEN": "dp.st." + "c" * 44,
            "PLANETSCALE_TOKEN": "pscale_pw_" + "d" * 40,
            "LINEAR_TOKEN": "lin_api_" + "e" * 44,
        }
        for expected_type, sample in samples.items():
            found = {f.type for f in scan(f"token = {sample}")}
            self.assertIn(
                expected_type, found,
                f"{expected_type} не обнаружен для сэмпла {sample!r}: {found}",
            )


class ComplianceGrouping(unittest.TestCase):
    def test_report_groups_cpf_cnpj_under_gdpr_hipaa_ccpa(self):
        result = redact(f"CPF {CPF} e CNPJ {CNPJ}")
        report = result.report()
        compliance = report["compliance"]
        for reg in ("GDPR", "HIPAA", "CCPA"):
            self.assertIn(reg, compliance, f"{reg} отсутствует в compliance")
            self.assertEqual(
                compliance[reg], ["CNPJ_BR", "CPF_BR"],
                f"{reg} должен группировать оба бразильских ID отсортированно",
            )

    def test_classify_matches_report_for_same_types(self):
        # Прямой classify даёт ту же группировку, что и report().
        result = redact(f"CPF {CPF} e CNPJ {CNPJ}")
        types = {f.type for f in result.findings}
        self.assertEqual(result.report()["compliance"], classify(types))

    def test_crypto_type_maps_to_gdpr_only(self):
        # TRON/SOLANA — crypto: GDPR покрывает crypto, HIPAA/CCPA — нет.
        regs = regulations_for("TRON_ADDRESS")
        self.assertIn("GDPR", regs)
        self.assertNotIn("HIPAA", regs)
        self.assertNotIn("CCPA", regs)


class CliTypesOutput(unittest.TestCase):
    def _run_types(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["types"])
        return code, buf.getvalue()

    def test_new_types_appear_in_types_command(self):
        code, out = self._run_types()
        self.assertEqual(code, 0)
        for t in ALL_NEW_TYPES:
            self.assertIn(t, out, f"тип {t} отсутствует в выводе `datashield types`")

    def test_types_output_lines_match_catalog_type_count(self):
        # Число непустых строк == число уникальных типов в каталоге (динамически).
        catalog_types = {i.detector.type for i in build_catalog(Config())}
        _, out = self._run_types()
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), len(catalog_types))

    def test_gov_id_line_shows_category_and_severity(self):
        _, out = self._run_types()
        # Строка CPF_BR должна содержать категорию government_id и критичность high.
        cpf_line = next(ln for ln in out.splitlines() if "CPF_BR" in ln)
        self.assertIn("government_id", cpf_line)
        self.assertIn("high", cpf_line)


if __name__ == "__main__":
    unittest.main()
