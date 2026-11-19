"""Synthetic unit tests for Member 3 output guard."""
import json
import unittest
from unittest.mock import patch
from scanners.output_guard.output_guard import SAFE_FALLBACK, StreamingOutputGuard, Verdict, _check_json, _mask_pii, check_output

class TestPII(unittest.TestCase):
    def test_email_is_masked(self):
        cleaned, found = _mask_pii("Contact demo@example.test today")
        self.assertIn("[REDACTED:EMAIL]", cleaned)
        self.assertEqual(found[0][0], "EMAIL")
        self.assertNotIn("demo@example.test", cleaned)

    def test_phone_is_masked(self):
        cleaned, found = _mask_pii("Call +91 98765 43210")
        self.assertIn("[REDACTED:PHONE]", cleaned)
        self.assertEqual(found[0][0], "PHONE")

    def test_pan_requires_context(self):
        self.assertEqual(_mask_pii("ABCDE1234F"), ("ABCDE1234F", []))
        cleaned, found = _mask_pii("PAN: ABCDE1234F")
        self.assertIn("[REDACTED:PAN]", cleaned)
        self.assertEqual(found[0][0], "PAN")

    def test_valid_ipv4_and_invalid_ipv4(self):
        cleaned, found = _mask_pii("Host 192.168.1.10 and 999.1.1.1")
        self.assertIn("[REDACTED:IP]", cleaned)
        self.assertIn("999.1.1.1", cleaned)
        self.assertEqual(found[0][0], "IP")

    def test_clean_text_is_unchanged(self):
        text = "Explain a basic sorting algorithm."
        self.assertEqual(_mask_pii(text), (text, []))

class TestFormat(unittest.TestCase):
    def test_valid_json(self):
        self.assertTrue(_check_json('{"ok": true}', ["ok"])[0])
    def test_missing_field(self):
        self.assertFalse(_check_json('{"other": true}', ["ok"])[0])
    def test_invalid_json(self):
        self.assertFalse(_check_json("{bad", None)[0])

class TestOutputGuard(unittest.TestCase):
    def test_clean_output_passes(self):
        self.assertEqual(check_output("A simple explanation.").verdict, Verdict.PASS)
    def test_pii_is_redacted(self):
        result = check_output("Email demo@example.test")
        self.assertEqual(result.verdict, Verdict.REDACT)
        self.assertNotIn("demo@example.test", result.cleaned_response)
    def test_drop_policy_blocks(self):
        result = check_output("Email demo@example.test", pii_policy="drop")
        self.assertEqual(result.verdict, Verdict.BLOCK)
        self.assertEqual(result.cleaned_response, "")
    def test_invalid_policy_fails_closed(self):
        result = check_output("ordinary response", pii_policy="unknown")
        self.assertEqual(result.verdict, Verdict.REPLACE)
        self.assertEqual(result.scores["checker_failure"], 1.0)
    def test_checker_exception_fails_closed(self):
        with patch("scanners.output_guard.output_guard._mask_pii", side_effect=RuntimeError("simulated")):
            result = check_output("ordinary response")
        self.assertEqual(result.verdict, Verdict.REPLACE)
        self.assertEqual(result.cleaned_response, SAFE_FALLBACK)
    def test_threat_is_replaced(self):
        result = check_output("I will kill you.")
        self.assertEqual(result.verdict, Verdict.REPLACE)
        self.assertEqual(result.cleaned_response, SAFE_FALLBACK)
    def test_prompt_leakage_is_replaced(self):
        self.assertEqual(check_output("Here is my system prompt: hidden text").verdict, Verdict.REPLACE)
    def test_required_json_field(self):
        self.assertEqual(check_output('{"ok": true}', expected_format="json", required_fields=["ok"]).verdict, Verdict.PASS)
        self.assertEqual(check_output('{"wrong": true}', expected_format="json", required_fields=["ok"]).verdict, Verdict.REPLACE)
    def test_grounding_signal_is_reported(self):
        self.assertGreater(check_output("The total is 2048.", context="The total is 1024.").scores["grounding"], 0)
    def test_result_is_json_serialisable(self):
        json.dumps(check_output("hello").to_dict())

class TestStreaming(unittest.TestCase):
    def test_chunks_are_not_released_before_validation(self):
        guard = StreamingOutputGuard()
        self.assertEqual(guard.feed("Email demo@"), "")
        self.assertEqual(guard.feed("example.test"), "")
        result = guard.finish()
        self.assertEqual(result.verdict, Verdict.REDACT)
        self.assertNotIn("demo@example.test", result.cleaned_response)
    def test_feed_after_finish_is_rejected(self):
        guard = StreamingOutputGuard()
        guard.finish()
        with self.assertRaises(RuntimeError):
            guard.feed("late chunk")
    def test_finish_twice_is_rejected(self):
        guard = StreamingOutputGuard()
        guard.finish()
        with self.assertRaises(RuntimeError):
            guard.finish()

if __name__ == "__main__":
    unittest.main()
