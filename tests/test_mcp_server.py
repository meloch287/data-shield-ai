"""Tests for datashield.integrations.mcp_server.

Exercises the pure JSON-RPC 2.0 handle() function and the serve_stdio() loop.
All assertions reflect the ACTUAL behavior of the implementation (verified
against datashield/integrations/mcp_server.py and its dependencies):

  - initialize -> protocolVersion + capabilities + serverInfo(name, version)
  - tools/list -> redact + scan, each with an inputSchema
  - tools/call redact -> masks (placeholder strategy by default), honors
    strategy / preset / min_severity
  - tools/call scan -> JSON array of {type, category, severity, preview} and
    never leaks the raw matched value
  - unknown tool -> JSON-RPC error -32602
  - unknown method (with id) -> JSON-RPC error -32601
  - notifications/initialized and any notification (no id) -> None
  - ping -> {}
  - serve_stdio() over newline-delimited JSON via io.StringIO

stdlib unittest only.
"""
from __future__ import annotations

import io
import json
import unittest

from datashield import __version__
from datashield.integrations.mcp_server import (
    PROTOCOL_VERSION,
    handle,
    serve_stdio,
)


def _req(method, request_id=None, params=None):
    """Build a JSON-RPC request dict. id omitted -> notification."""
    obj = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        obj["id"] = request_id
    if params is not None:
        obj["params"] = params
    return obj


def _call(name, arguments, request_id=1):
    return handle(_req("tools/call", request_id, {"name": name, "arguments": arguments}))


def _redact_text(arguments, request_id=1):
    """Run a redact tools/call and return the masked text string."""
    resp = _call("redact", arguments, request_id)
    return resp["result"]["content"][0]["text"]


def _scan_payload(text, request_id=1):
    """Run a scan tools/call and return the parsed JSON array."""
    resp = _call("scan", {"text": text}, request_id)
    inner = resp["result"]["content"][0]["text"]
    return json.loads(inner)


class InitializeTests(unittest.TestCase):
    def test_initialize_returns_protocol_version(self):
        resp = handle(_req("initialize", 1))
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 1)
        result = resp["result"]
        self.assertEqual(result["protocolVersion"], PROTOCOL_VERSION)
        self.assertEqual(result["protocolVersion"], "2024-11-05")

    def test_initialize_server_info(self):
        result = handle(_req("initialize", 7))["result"]
        info = result["serverInfo"]
        self.assertEqual(info["name"], "data-shield-ai")
        self.assertEqual(info["version"], __version__)

    def test_initialize_advertises_tools_capability(self):
        result = handle(_req("initialize", 1))["result"]
        self.assertIn("capabilities", result)
        self.assertIn("tools", result["capabilities"])

    def test_initialize_echoes_request_id(self):
        # id may be any JSON value; here a string.
        resp = handle(_req("initialize", "abc"))
        self.assertEqual(resp["id"], "abc")


class PingTests(unittest.TestCase):
    def test_ping_returns_empty_result(self):
        resp = handle(_req("ping", 2))
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 2)
        self.assertEqual(resp["result"], {})
        self.assertNotIn("error", resp)


class NotificationTests(unittest.TestCase):
    def test_notifications_initialized_returns_none(self):
        self.assertIsNone(handle(_req("notifications/initialized")))

    def test_notifications_initialized_with_id_still_none(self):
        # The method branch returns before the id-based fallback, so even with
        # an id present it yields None.
        self.assertIsNone(handle(_req("notifications/initialized", 99)))

    def test_unknown_notification_without_id_returns_none(self):
        # Unknown method but no id -> treated as a notification -> None.
        self.assertIsNone(handle(_req("some/unknown/notification")))


class ToolsListTests(unittest.TestCase):
    def setUp(self):
        self.resp = handle(_req("tools/list", 3))
        self.tools = self.resp["result"]["tools"]
        self.by_name = {t["name"]: t for t in self.tools}

    def test_lists_redact_and_scan(self):
        self.assertEqual(set(self.by_name), {"redact", "scan"})

    def test_each_tool_has_input_schema(self):
        for name, tool in self.by_name.items():
            with self.subTest(tool=name):
                self.assertIn("inputSchema", tool)
                schema = tool["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertIn("text", schema["properties"])
                self.assertIn("text", schema["required"])

    def test_each_tool_has_description(self):
        for name, tool in self.by_name.items():
            with self.subTest(tool=name):
                self.assertTrue(tool["description"])

    def test_redact_schema_advertises_strategy_enum(self):
        schema = self.by_name["redact"]["inputSchema"]
        strat = schema["properties"]["strategy"]
        self.assertEqual(
            set(strat["enum"]),
            {"placeholder", "pseudonym", "partial", "hash", "remove"},
        )
        # preset and min_severity are accepted optional inputs.
        self.assertIn("preset", schema["properties"])
        self.assertIn("min_severity", schema["properties"])


class RedactToolTests(unittest.TestCase):
    def test_default_strategy_is_placeholder(self):
        masked = _redact_text({"text": "email a@b.com and card 4111111111111111"})
        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[CREDIT_CARD_1]", masked)
        self.assertNotIn("a@b.com", masked)
        self.assertNotIn("4111111111111111", masked)

    def test_response_shape_is_text_content(self):
        resp = _call("redact", {"text": "a@b.com"})
        content = resp["result"]["content"]
        self.assertEqual(content[0]["type"], "text")
        self.assertIsInstance(content[0]["text"], str)

    def test_strategy_remove_drops_match(self):
        masked = _redact_text({"text": "email a@b.com", "strategy": "remove"})
        self.assertNotIn("a@b.com", masked)
        self.assertNotIn("[EMAIL", masked)
        self.assertEqual(masked, "email ")

    def test_strategy_hash_produces_hashed_placeholder(self):
        masked = _redact_text({"text": "email a@b.com", "strategy": "hash"})
        self.assertNotIn("a@b.com", masked)
        # hash strategy keeps the typed prefix but adds a hex digest suffix.
        self.assertIn("[EMAIL_", masked)
        self.assertNotEqual(masked, "email [EMAIL_1]")

    def test_strategy_pseudonym_yields_fake_value(self):
        masked = _redact_text({"text": "mail a@b.com", "strategy": "pseudonym"})
        self.assertNotIn("a@b.com", masked)
        # pseudonym produces a plausible-but-fake value, not a bracket placeholder.
        self.assertNotIn("[EMAIL", masked)

    def test_min_severity_high_skips_lower_severity(self):
        # EMAIL is medium severity; CREDIT_CARD is critical. With min_severity
        # 'high', the email is left untouched while the card is still masked.
        masked = _redact_text(
            {
                "text": "email a@b.com card 4111111111111111",
                "min_severity": "high",
            }
        )
        self.assertIn("a@b.com", masked)
        self.assertIn("[CREDIT_CARD_1]", masked)

    def test_preset_secrets_only_limits_scope(self):
        # secrets-only preset masks only secret-type findings. An email stays,
        # an Anthropic API key gets masked.
        text = (
            "mail a@b.com tok "
            "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"
        )
        masked = _redact_text({"text": text, "preset": "secrets-only"})
        self.assertIn("a@b.com", masked)
        self.assertIn("[ANTHROPIC_KEY_1]", masked)

    def test_invalid_preset_returns_iserror_content_not_jsonrpc_error(self):
        # An unknown preset raises inside _call_tool and is surfaced as an
        # isError tool result (not a JSON-RPC -32xxx error).
        resp = _call("redact", {"text": "x", "preset": "no-such-preset"})
        self.assertNotIn("error", resp)
        self.assertTrue(resp["result"].get("isError"))
        self.assertIn("content", resp["result"])

    def test_stable_placeholder_numbering_within_request(self):
        # Same value -> same placeholder; distinct value -> next number.
        masked = _redact_text({"text": "a@b.com then c@d.com then a@b.com again"})
        self.assertEqual(masked, "[EMAIL_1] then [EMAIL_2] then [EMAIL_1] again")

    def test_missing_text_argument_defaults_to_empty(self):
        # Arguments without 'text' default text to "" -> nothing to mask.
        resp = _call("redact", {})
        self.assertEqual(resp["result"]["content"][0]["text"], "")


class ScanToolTests(unittest.TestCase):
    def test_returns_json_array_with_expected_keys(self):
        payload = _scan_payload("email a@b.com card 4111111111111111")
        self.assertIsInstance(payload, list)
        self.assertTrue(payload)
        for entry in payload:
            self.assertEqual(
                set(entry), {"type", "category", "severity", "preview"}
            )

    def test_scan_reports_type_category_severity(self):
        payload = _scan_payload("email a@b.com")
        types = {e["type"] for e in payload}
        self.assertIn("EMAIL", types)
        email = next(e for e in payload if e["type"] == "EMAIL")
        self.assertEqual(email["category"], "contact")
        self.assertEqual(email["severity"], "medium")

    def test_credit_card_is_critical_financial(self):
        payload = _scan_payload("card 4111111111111111")
        card = next(e for e in payload if e["type"] == "CREDIT_CARD")
        self.assertEqual(card["category"], "financial")
        self.assertEqual(card["severity"], "critical")

    def test_scan_never_leaks_raw_value(self):
        raw_email = "secretuser@example.org"
        raw_card = "4111111111111111"
        resp = _call("scan", {"text": f"{raw_email} {raw_card}"})
        blob = resp["result"]["content"][0]["text"]
        self.assertNotIn(raw_email, blob)
        self.assertNotIn(raw_card, blob)
        # preview is a redacted form keeping only the first character.
        payload = json.loads(blob)
        for entry in payload:
            self.assertIn("*", entry["preview"])

    def test_scan_clean_text_returns_empty_array(self):
        payload = _scan_payload("nothing sensitive here at all")
        self.assertEqual(payload, [])


class ErrorHandlingTests(unittest.TestCase):
    def test_unknown_tool_returns_invalid_params(self):
        resp = _call("does_not_exist", {"text": "x"}, request_id=42)
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 42)
        self.assertNotIn("result", resp)
        self.assertEqual(resp["error"]["code"], -32602)

    def test_unknown_method_with_id_returns_method_not_found(self):
        resp = handle(_req("frobnicate", 11))
        self.assertEqual(resp["id"], 11)
        self.assertNotIn("result", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_empty_tool_name_is_invalid_params(self):
        resp = handle(_req("tools/call", 12, {"arguments": {"text": "x"}}))
        self.assertEqual(resp["error"]["code"], -32602)


class ServeStdioTests(unittest.TestCase):
    def _run(self, requests):
        data = "".join(json.dumps(r) + "\n" for r in requests)
        out = io.StringIO()
        serve_stdio(io.StringIO(data), out)
        return [
            json.loads(line)
            for line in out.getvalue().splitlines()
            if line.strip()
        ]

    def test_multiple_requests_round_trip(self):
        responses = self._run(
            [
                _req("initialize", 1),
                _req("notifications/initialized"),  # no output expected
                _req("ping", 2),
                _req("tools/list", 3),
                _req("tools/call", 4, {"name": "redact", "arguments": {"text": "a@b.com"}}),
            ]
        )
        # The notification produces no response line -> 4 responses, not 5.
        self.assertEqual(len(responses), 4)
        ids = [r["id"] for r in responses]
        self.assertEqual(ids, [1, 2, 3, 4])

        init, ping, tools, redact = responses
        self.assertEqual(init["result"]["serverInfo"]["name"], "data-shield-ai")
        self.assertEqual(ping["result"], {})
        self.assertEqual(
            {t["name"] for t in tools["result"]["tools"]}, {"redact", "scan"}
        )
        self.assertEqual(
            redact["result"]["content"][0]["text"], "[EMAIL_1]"
        )

    def test_blank_lines_are_skipped(self):
        data = "\n\n" + json.dumps(_req("ping", 1)) + "\n\n"
        out = io.StringIO()
        serve_stdio(io.StringIO(data), out)
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["id"], 1)

    def test_invalid_json_line_is_ignored(self):
        data = "not json at all\n" + json.dumps(_req("ping", 5)) + "\n"
        out = io.StringIO()
        serve_stdio(io.StringIO(data), out)
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["id"], 5)

    def test_notification_only_input_produces_no_output(self):
        out = io.StringIO()
        serve_stdio(
            io.StringIO(json.dumps(_req("notifications/initialized")) + "\n"),
            out,
        )
        self.assertEqual(out.getvalue().strip(), "")


if __name__ == "__main__":
    unittest.main()
