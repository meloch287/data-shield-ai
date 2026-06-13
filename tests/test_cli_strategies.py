"""CLI tests for masking strategies, the --vault file, and the restore command.

These exercise `datashield.cli.main(argv)` end-to-end (Block B features):
  * redact --strategy {placeholder,pseudonym,partial,hash,remove}
  * redact --reversible
  * redact --vault FILE  (writes a JSON replacement->original map; forces reversible)
  * restore --vault FILE [--in] [--out]  (round-trips masked text back to original)

Behavior is asserted against the real implementation in datashield/, including a
documented data-corruption bug in the `remove` + `--vault` + `restore` path.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datashield.cli import main


def run(argv, stdin_text=None):
    """Drive cli.main capturing stdout/stderr; optionally feed stdin."""
    out, err = io.StringIO(), io.StringIO()
    real_stdin = None
    if stdin_text is not None:
        real_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        if stdin_text is not None:
            sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


# A sample with two distinct sensitive values of different types.
SAMPLE = "пиши на a@b.com и звони +79161234567"


class StrategyMaskingTests(unittest.TestCase):
    """redact --strategy <name> produces the strategy-specific masked output."""

    def test_placeholder_strategy(self):
        code, out, err = run(["redact", "--strategy", "placeholder"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[PHONE_RU_1]", out)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("+79161234567", out)

    def test_placeholder_is_default_strategy(self):
        # No --strategy flag: default is placeholder.
        code, out, _ = run(["redact"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[PHONE_RU_1]", out)

    def test_pseudonym_strategy_format_preserving(self):
        code, out, err = run(["redact", "--strategy", "pseudonym"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Email becomes a fake @example.invalid address; raw value gone.
        self.assertIn("@example.invalid", out)
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("+79161234567", out)
        # No bracketed placeholder tokens for pseudonymisation.
        self.assertNotIn("[EMAIL", out)

    def test_pseudonym_is_deterministic_across_runs(self):
        # Same default key + same value => identical fake (stable for downstream AI).
        _, out1, _ = run(["redact", "--strategy", "pseudonym"], stdin_text="a@b.com")
        _, out2, _ = run(["redact", "--strategy", "pseudonym"], stdin_text="a@b.com")
        self.assertEqual(out1, out2)
        self.assertIn("@example.invalid", out1)

    def test_partial_strategy_keeps_tail_visible(self):
        code, out, err = run(["redact", "--strategy", "partial"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Last 4 alphanumerics of the phone stay visible, separators preserved.
        self.assertIn("4567", out)
        self.assertIn("+", out)
        self.assertIn("*", out)
        self.assertNotIn("+79161234567", out)

    def test_hash_strategy_tokens(self):
        code, out, err = run(["redact", "--strategy", "hash"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Hash tokens look like [TYPE_<10 hex chars>].
        self.assertRegex(out, r"\[EMAIL_[0-9a-f]{10}\]")
        self.assertRegex(out, r"\[PHONE_RU_[0-9a-f]{10}\]")
        self.assertNotIn("a@b.com", out)

    def test_hash_strategy_is_deterministic(self):
        _, out1, _ = run(["redact", "--strategy", "hash"], stdin_text="a@b.com")
        _, out2, _ = run(["redact", "--strategy", "hash"], stdin_text="a@b.com")
        self.assertEqual(out1, out2)

    def test_remove_strategy_deletes_values(self):
        code, out, err = run(["redact", "--strategy", "remove"], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Sensitive substrings are excised entirely (default marker is "").
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("+79161234567", out)
        self.assertNotIn("[EMAIL", out)
        # The non-sensitive scaffolding text remains.
        self.assertIn("пиши на", out)
        self.assertIn("звони", out)

    def test_stable_value_gets_single_placeholder(self):
        # The same value twice => one placeholder reused (request-stable).
        code, out, _ = run(["redact"], stdin_text="a@b.com и снова a@b.com")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("[EMAIL_1]"), 2)
        self.assertNotIn("[EMAIL_2]", out)


class InvalidStrategyTests(unittest.TestCase):
    """An unknown --strategy value is rejected by argparse (exit code 2)."""

    def test_invalid_strategy_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            run(["redact", "--strategy", "bogus"], stdin_text="a@b.com")
        self.assertEqual(ctx.exception.code, 2)

    def test_invalid_strategy_reports_choices(self):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit):
            with redirect_stdout(out), redirect_stderr(err):
                main(["redact", "--strategy", "bogus"])
        # argparse prints the valid choices to stderr.
        combined = out.getvalue() + err.getvalue()
        self.assertIn("bogus", combined)
        self.assertIn("placeholder", combined)


class VaultRoundTripTests(unittest.TestCase):
    """--vault writes a JSON file that restore round-trips back to the original."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def _vault_path(self, name="vault.json"):
        return os.path.join(self.dir, name)

    def test_vault_file_is_json_replacement_to_original_map(self):
        vault = self._vault_path()
        code, masked, _ = run(["redact", "--vault", vault], stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        with open(vault, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIsInstance(data, dict)
        # Keys are the placeholders that appear in the masked text;
        # values are the raw originals.
        self.assertEqual(data["[EMAIL_1]"], "a@b.com")
        self.assertEqual(data["[PHONE_RU_1]"], "+79161234567")
        self.assertIn("[EMAIL_1]", masked)

    def test_placeholder_vault_round_trip(self):
        vault = self._vault_path()
        _, masked, _ = run(["redact", "--strategy", "placeholder", "--vault", vault],
                           stdin_text=SAMPLE)
        code, restored, err = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(restored, SAMPLE)

    def test_pseudonym_vault_round_trip(self):
        vault = self._vault_path()
        _, masked, _ = run(["redact", "--strategy", "pseudonym", "--vault", vault],
                           stdin_text=SAMPLE)
        self.assertNotIn("a@b.com", masked)
        code, restored, _ = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        self.assertEqual(restored, SAMPLE)

    def test_hash_vault_round_trip(self):
        vault = self._vault_path()
        _, masked, _ = run(["redact", "--strategy", "hash", "--vault", vault],
                           stdin_text=SAMPLE)
        code, restored, _ = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        self.assertEqual(restored, SAMPLE)

    def test_vault_forces_reversibility_even_without_flag(self):
        # --vault alone (no --reversible) still produces a populated vault.
        vault = self._vault_path()
        run(["redact", "--strategy", "placeholder", "--vault", vault], stdin_text=SAMPLE)
        with open(vault, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertTrue(data)  # non-empty

    def test_reversible_flag_does_not_change_masked_text(self):
        # --reversible only affects the (in-memory) vault, not the emitted text.
        _, plain, _ = run(["redact", "--strategy", "placeholder"], stdin_text=SAMPLE)
        _, rev, _ = run(["redact", "--strategy", "placeholder", "--reversible"],
                        stdin_text=SAMPLE)
        self.assertEqual(plain, rev)

    def test_round_trip_through_files(self):
        # redact --out FILE, then restore --in FILE --out FILE2.
        vault = self._vault_path()
        masked_file = os.path.join(self.dir, "masked.txt")
        restored_file = os.path.join(self.dir, "restored.txt")
        code, _, _ = run(["redact", "--vault", vault, "--out", masked_file],
                         stdin_text=SAMPLE)
        self.assertEqual(code, 0)
        with open(masked_file, encoding="utf-8") as fh:
            self.assertNotIn("a@b.com", fh.read())
        code, _, _ = run(["restore", "--vault", vault,
                          "--in", masked_file, "--out", restored_file])
        self.assertEqual(code, 0)
        with open(restored_file, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), SAMPLE)

    def test_repeated_value_round_trips(self):
        vault = self._vault_path()
        text = "a@b.com и снова a@b.com"
        _, masked, _ = run(["redact", "--vault", vault], stdin_text=text)
        self.assertEqual(masked.count("[EMAIL_1]"), 2)
        code, restored, _ = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        self.assertEqual(restored, text)


class RestoreCommandTests(unittest.TestCase):
    """restore command argument handling and validation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def test_restore_requires_vault(self):
        with self.assertRaises(SystemExit) as ctx:
            run(["restore"], stdin_text="anything")
        self.assertEqual(ctx.exception.code, 2)

    def test_restore_rejects_non_object_vault(self):
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump([1, 2, 3], fh)
        code, _, err = run(["restore", "--vault", bad], stdin_text="x")
        self.assertEqual(code, 2)
        self.assertIn("JSON", err)

    def test_restore_with_empty_vault_is_noop(self):
        empty = os.path.join(self.dir, "empty.json")
        with open(empty, "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        code, out, _ = run(["restore", "--vault", empty], stdin_text="нет токенов")
        self.assertEqual(code, 0)
        self.assertEqual(out, "нет токенов")

    def test_restore_missing_vault_file_errors(self):
        missing = os.path.join(self.dir, "does_not_exist.json")
        # cli.main maps OSError to exit code 1 (file open fails before json.load).
        code, _, err = run(["restore", "--vault", missing], stdin_text="x")
        self.assertEqual(code, 1)
        self.assertIn("Ошибка ввода-вывода", err)

    def test_restore_only_replaces_known_tokens(self):
        # Tokens not in the vault are passed through untouched.
        vault = os.path.join(self.dir, "v.json")
        with open(vault, "w", encoding="utf-8") as fh:
            json.dump({"[EMAIL_1]": "a@b.com"}, fh)
        code, out, _ = run(["restore", "--vault", vault],
                           stdin_text="до [EMAIL_1] и [PHONE_RU_1] после")
        self.assertEqual(code, 0)
        self.assertEqual(out, "до a@b.com и [PHONE_RU_1] после")


class LossyStrategyVaultTests(unittest.TestCase):
    """Vault behavior for the lossy strategies (partial, remove).

    `--vault` forces reversibility regardless of the strategy's own
    `reversible` flag, so even lossy strategies emit a vault. For `partial`
    the unique masked token still round-trips; for `remove` the vault is
    BROKEN (see test below).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def test_partial_vault_happens_to_round_trip(self):
        # partial replacements are unique here, so restore can recover them.
        vault = os.path.join(self.dir, "v.json")
        _, masked, _ = run(["redact", "--strategy", "partial", "--vault", vault],
                           stdin_text=SAMPLE)
        with open(vault, encoding="utf-8") as fh:
            data = json.load(fh)
        # Masked tokens (e.g. "*@b.com") map back to originals.
        self.assertEqual(data["*@b.com"], "a@b.com")
        code, restored, _ = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        self.assertEqual(restored, SAMPLE)

    def test_remove_vault_has_empty_string_key(self):
        # remove replaces every finding with "", so the vault key is "".
        vault = os.path.join(self.dir, "v.json")
        run(["redact", "--strategy", "remove", "--vault", vault], stdin_text=SAMPLE)
        with open(vault, encoding="utf-8") as fh:
            data = json.load(fh)
        # All findings collide on the empty-string replacement; only one survives.
        self.assertIn("", data)
        self.assertEqual(len(data), 1)

    def test_remove_vault_restore_corrupts_text_BUG(self):
        # BUG: `redact --strategy remove --vault` writes {"": <original>}.
        # `restore` then does masked_text.replace("", original), which splices
        # the original between EVERY character instead of restoring cleanly.
        # We assert the actual (buggy) corrupted output so the regression is
        # captured; the restored text is NOT equal to the original.
        vault = os.path.join(self.dir, "v.json")
        text = "пиши на a@b.com"
        _, masked, _ = run(["redact", "--strategy", "remove", "--vault", vault],
                           stdin_text=text)
        self.assertEqual(masked, "пиши на ")
        code, restored, _ = run(["restore", "--vault", vault], stdin_text=masked)
        self.assertEqual(code, 0)
        # Corruption: the original is inserted around every char of the masked text.
        self.assertNotEqual(restored, text)
        self.assertIn("a@b.com", restored)
        self.assertGreater(restored.count("a@b.com"), 1)


if __name__ == "__main__":
    unittest.main()
