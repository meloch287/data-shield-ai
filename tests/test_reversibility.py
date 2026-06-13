"""Тесты обратимости (vault round-trip).

Block B вводит обратимую маскировку: при reversible=True движок собирает vault
(замена → оригинал), а restore() подставляет оригиналы обратно. Проверяем:

* точный round-trip для обратимых стратегий (placeholder, pseudonym, hash);
* модульный restore(masked, vault) эквивалентен result.restore();
* несколько значений и повторы восстанавливаются корректно;
* подстановка от длинных к коротким не портит вложенные токены;
* restore с пустым vault — тождество;
* lossy-стратегии (partial, remove) помечены reversible=False, и для них
  round-trip НЕ гарантируется (документируем фактическое поведение);
* vault действительно отображает замену → оригинал.

Тесты опираются на реальное поведение источников в datashield/.
"""
import unittest

from datashield import Config, build_engine, redact, restore, scan
from datashield.detectors.base import Finding
from datashield.engine import restore as engine_restore
from datashield.masking import ReplacementContext
from datashield.strategies import (
    HashStrategy,
    PartialStrategy,
    PlaceholderStrategy,
    PseudonymStrategy,
    RemoveStrategy,
    make_strategy,
)

REVERSIBLE_STRATEGIES = ("placeholder", "pseudonym", "hash")
LOSSY_STRATEGIES = ("partial", "remove")

# Текст с несколькими типами и одним повтором email.
SAMPLE = (
    "пиши на a@b.com, дублирую a@b.com; второй c@d.com; "
    "телефон +7 909 123 45 67; карта 4111 1111 1111 1111"
)


class RoundTripReversibleStrategiesTests(unittest.TestCase):
    """result.restore() и module restore() точно возвращают оригинал."""

    def test_result_restore_exact_for_each_reversible_strategy(self):
        for name in REVERSIBLE_STRATEGIES:
            with self.subTest(strategy=name):
                result = redact(SAMPLE, strategy=name, reversible=True)
                # Маскировка действительно что-то спрятала.
                self.assertNotEqual(result.masked_text, SAMPLE)
                # Round-trip побайтово равен оригиналу.
                self.assertEqual(result.restore(), SAMPLE)

    def test_module_restore_matches_result_restore(self):
        for name in REVERSIBLE_STRATEGIES:
            with self.subTest(strategy=name):
                result = redact(SAMPLE, strategy=name, reversible=True)
                via_module = restore(result.masked_text, result.vault)
                self.assertEqual(via_module, SAMPLE)
                self.assertEqual(via_module, result.restore())

    def test_engine_restore_alias_is_same_function(self):
        # datashield.restore и datashield.engine.restore — один и тот же объект.
        self.assertIs(restore, engine_restore)

    def test_restore_into_custom_text_argument(self):
        # result.restore(text) восстанавливает в произвольном тексте, не только
        # в собственном masked_text.
        result = redact("один a@b.com", strategy="placeholder", reversible=True)
        token = next(iter(result.vault))
        custom = f"prefix {token} middle {token} suffix"
        self.assertEqual(
            result.restore(custom), "prefix a@b.com middle a@b.com suffix"
        )


class VaultMappingTests(unittest.TestCase):
    """vault — это замена → оригинал, а placeholders — замена → тип."""

    def test_vault_maps_replacement_to_original(self):
        result = redact("email a@b.com", strategy="placeholder", reversible=True)
        self.assertEqual(result.vault, {"[EMAIL_1]": "a@b.com"})

    def test_vault_keys_are_replacements_present_in_masked_text(self):
        result = redact(SAMPLE, strategy="placeholder", reversible=True)
        self.assertTrue(result.vault)
        for replacement, original in result.vault.items():
            # Каждый ключ vault реально встречается в маскированном тексте...
            self.assertIn(replacement, result.masked_text)
            # ...а значение — оригинал, которого там уже нет.
            self.assertNotIn(original, result.masked_text)

    def test_placeholders_map_replacement_to_type_not_value(self):
        # placeholders — безопасная карта (замена → тип), без сырых значений.
        result = redact("email a@b.com", strategy="placeholder", reversible=True)
        self.assertEqual(result.placeholders, {"[EMAIL_1]": "EMAIL"})
        self.assertNotIn("a@b.com", result.placeholders.values())

    def test_replacementcontext_vault_and_mapping_directions(self):
        ctx = ReplacementContext(PlaceholderStrategy())
        finding = Finding("EMAIL", 0, 7, "a@b.com", 0.99, "regex")
        repl = ctx.replacement_for(finding)
        self.assertEqual(repl, "[EMAIL_1]")
        # vault: замена → оригинал; mapping: замена → тип.
        self.assertEqual(ctx.vault(), {"[EMAIL_1]": "a@b.com"})
        self.assertEqual(ctx.mapping, {"[EMAIL_1]": "EMAIL"})


class MultipleValuesAndRepeatsTests(unittest.TestCase):
    """Несколько различных значений и повторы восстанавливаются корректно."""

    def test_repeated_value_shares_one_replacement(self):
        result = redact(
            "a@b.com c@d.com a@b.com", strategy="placeholder", reversible=True
        )
        # Повтор a@b.com получает один и тот же плейсхолдер.
        self.assertEqual(result.masked_text, "[EMAIL_1] [EMAIL_2] [EMAIL_1]")
        self.assertEqual(len(result.vault), 2)
        self.assertEqual(result.restore(), "a@b.com c@d.com a@b.com")

    def test_many_distinct_values_round_trip(self):
        # 12 различных email: проверяет нумерацию >9 и восстановление всех.
        original = " ".join(f"user{i}@x.com" for i in range(1, 13))
        result = redact(original, strategy="placeholder", reversible=True)
        self.assertEqual(len(result.vault), 12)
        self.assertEqual(result.restore(), original)

    def test_pseudonym_repeat_is_stable_and_reversible(self):
        # Один и тот же оригинал → один и тот же фейк → корректный round-trip.
        original = "a@b.com и снова a@b.com"
        result = redact(original, strategy="pseudonym", reversible=True)
        # Ровно одна запись в vault, потому что значение совпадает.
        self.assertEqual(len(result.vault), 1)
        fake = next(iter(result.vault))
        self.assertEqual(result.masked_text.count(fake), 2)
        self.assertEqual(result.restore(), original)


class LongestFirstReplacementTests(unittest.TestCase):
    """Подстановка от длинных замен к коротким защищает вложенные токены."""

    def test_nested_token_not_corrupted(self):
        # Короткая замена 'TOK1' является подстрокой длинной 'TOK11'. Если бы
        # restore шёл по коротким сначала, 'TOK11' превратился бы в 'SHORT1'.
        vault = {"TOK1": "SHORT", "TOK11": "LONG"}
        masked = "TOK11 then TOK1"
        self.assertEqual(restore(masked, vault), "LONG then SHORT")

    def test_longest_first_order_is_required(self):
        # Демонстрируем, что наивный порядок (по возрастанию) портит результат,
        # а реальный restore (по убыванию длины) — нет.
        vault = {"TOK1": "SHORT", "TOK11": "LONG"}
        masked = "TOK11"

        def naive(text, v):
            for key in sorted(v):  # 'TOK1' раньше 'TOK11'
                text = text.replace(key, v[key])
            return text

        self.assertEqual(naive(masked, vault), "SHORT1")  # испорчено
        self.assertEqual(restore(masked, vault), "LONG")  # корректно

    def test_real_redaction_with_overlapping_placeholder_numbers(self):
        # [EMAIL_1] и [EMAIL_10] существуют одновременно; round-trip должен быть
        # точным несмотря на численно вложенные имена.
        original = " ".join(f"u{i}@h.com" for i in range(1, 11))
        result = redact(original, strategy="placeholder", reversible=True)
        self.assertIn("[EMAIL_1]", result.vault)
        self.assertIn("[EMAIL_10]", result.vault)
        self.assertEqual(result.restore(), original)


class EmptyVaultIdentityTests(unittest.TestCase):
    """restore с пустым vault — тождественная функция."""

    def test_empty_vault_is_identity_module(self):
        text = "ничего не спрятано [EMAIL_1] остаётся"
        self.assertEqual(restore(text, {}), text)

    def test_empty_vault_is_identity_for_empty_text(self):
        self.assertEqual(restore("", {}), "")

    def test_default_redact_has_empty_vault(self):
        # reversible по умолчанию False → vault пустой, restore() ничего не меняет.
        result = redact("email a@b.com", strategy="placeholder")
        self.assertEqual(result.vault, {})
        self.assertEqual(result.restore(), result.masked_text)

    def test_restore_identity_when_no_replacement_present(self):
        # Vault непустой, но текст не содержит ни одной замены — возвращается как есть.
        text = "plain text without any tokens"
        self.assertEqual(restore(text, {"[EMAIL_1]": "a@b.com"}), text)


class ReversibleFlagTests(unittest.TestCase):
    """Флаг .reversible корректно проставлен на классах и через make_strategy."""

    def test_reversible_strategies_flag_true(self):
        self.assertTrue(PlaceholderStrategy.reversible)
        self.assertTrue(PseudonymStrategy.reversible)
        self.assertTrue(HashStrategy.reversible)

    def test_lossy_strategies_flag_false(self):
        self.assertFalse(PartialStrategy.reversible)
        self.assertFalse(RemoveStrategy.reversible)

    def test_make_strategy_preserves_reversible_flag(self):
        expected = {
            "placeholder": True,
            "pseudonym": True,
            "hash": True,
            "partial": False,
            "remove": False,
        }
        for name, flag in expected.items():
            with self.subTest(strategy=name):
                self.assertEqual(make_strategy(name).reversible, flag)


class LossyStrategiesNotGuaranteedTests(unittest.TestCase):
    """partial/remove лоссовые: round-trip НЕ гарантируется (документируем)."""

    def test_remove_round_trip_fails(self):
        # remove заменяет значение на маркер (по умолчанию ''), теряя его.
        original = "карта 4111 1111 1111 1111 тут"
        result = redact(original, strategy="remove", reversible=True)
        # Значение пропало из текста...
        self.assertNotIn("4111 1111 1111 1111", result.masked_text)
        # ...и restore НЕ возвращает оригинал (round-trip нарушен).
        self.assertNotEqual(result.restore(), original)

    def test_remove_empty_marker_vault_key_is_empty_string(self):
        # Лоссовость наглядна: ключ vault — пустая строка, что делает restore
        # бессмысленным (str.replace('', ...) вставляет всюду).
        result = redact("карта 4111 1111 1111 1111", strategy="remove", reversible=True)
        self.assertIn("", result.vault)
        self.assertEqual(result.vault[""], "4111 1111 1111 1111")

    def test_partial_collapses_distinct_values(self):
        # Два РАЗНЫХ значения с одинаковым хвостом дают одну и ту же маску —
        # информация теряется, поэтому partial не обратим в общем случае.
        strat = PartialStrategy(visible=4)
        f1 = Finding("PHONE", 0, 10, "0001234567", 0.9, "x")
        f2 = Finding("PHONE", 0, 10, "9991234567", 0.9, "x")
        self.assertEqual(strat.generate(f1, 1), strat.generate(f2, 2))

    def test_partial_round_trip_breaks_on_colliding_masks(self):
        # Два РАЗНЫХ значения с одинаковым хвостом и одинаковой структурой дают
        # одну и ту же маску → vault схлопывается в один ключ → restore не может
        # восстановить обе → round-trip нарушается (partial не обратим).
        original = "тел +7 916 111 00 02 и тел +7 916 222 00 02"
        result = redact(original, strategy="partial", reversible=True)
        # Убеждаемся, что оба телефона реально найдены (иначе кейс бессмысленен).
        self.assertEqual(sum(1 for f in result.findings if f.type == "PHONE_RU"), 2)
        # Маска у обоих одинаковая → один ключ vault → точное восстановление невозможно.
        self.assertEqual(len(result.vault), 1)
        self.assertNotEqual(result.restore(), original)


class ConfigDrivenReversibilityTests(unittest.TestCase):
    """reversible управляется через Config и переопределяется аргументом."""

    def test_config_reversible_true_populates_vault(self):
        cfg = Config(strategy="placeholder", reversible=True)
        result = redact("email a@b.com", config=cfg)
        self.assertEqual(result.vault, {"[EMAIL_1]": "a@b.com"})
        self.assertEqual(result.restore(), "email a@b.com")

    def test_config_reversible_false_empty_vault(self):
        cfg = Config(reversible=False)
        result = redact("email a@b.com", config=cfg)
        self.assertEqual(result.vault, {})

    def test_kwarg_overrides_config_reversible(self):
        # Явный reversible=True перекрывает Config(reversible=False).
        cfg = Config(reversible=False)
        result = redact("email a@b.com", config=cfg, reversible=True)
        self.assertNotEqual(result.vault, {})
        self.assertEqual(result.restore(), "email a@b.com")

    def test_build_engine_reversible_flag(self):
        engine = build_engine(reversible=True)
        result = engine.redact("email a@b.com")
        self.assertTrue(result.vault)
        self.assertEqual(result.restore(), "email a@b.com")


class PseudonymRestoreSemanticsTests(unittest.TestCase):
    """Псевдонимы выглядят как реальные данные, но vault восстанавливает оригинал."""

    def test_pseudonym_replacement_differs_from_original_but_restores(self):
        original = "почта a@b.com"
        result = redact(original, strategy="pseudonym", reversible=True)
        fake = next(iter(result.vault))
        # Фейк не равен оригиналу...
        self.assertNotEqual(fake, "a@b.com")
        # ...но vault хранит реальный оригинал и restore его возвращает.
        self.assertEqual(result.vault[fake], "a@b.com")
        self.assertEqual(result.restore(), original)

    def test_hash_replacement_is_typed_token_and_restores(self):
        original = "почта a@b.com"
        result = redact(original, strategy="hash", reversible=True)
        token = next(iter(result.vault))
        self.assertTrue(token.startswith("[EMAIL_"))
        self.assertEqual(result.vault[token], "a@b.com")
        self.assertEqual(result.restore(), original)


class NoFindingsTests(unittest.TestCase):
    """Когда нечего маскировать, vault пуст и restore — тождество."""

    def test_no_pii_empty_vault_and_identity(self):
        clean = "просто обычный текст без чувствительных данных"
        self.assertEqual(scan(clean), [])
        result = redact(clean, strategy="placeholder", reversible=True)
        self.assertEqual(result.masked_text, clean)
        self.assertEqual(result.vault, {})
        self.assertEqual(result.restore(), clean)


if __name__ == "__main__":
    unittest.main()
