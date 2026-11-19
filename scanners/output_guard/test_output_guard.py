"""Synthetic unit tests for Member 3 output guard."""
import json
import unittest

from scanners.output_guard.output_guard import (
    SAFE_FALLBACK, StreamingOutputGuard, Verdict, _check_json,
    _mask_pii, check_output,
)


class TestPII(unittest.TestCase):
    def test_email_is_masked(self):
        cleaned, found = _mask_pii("Contact demo@example.test today")
        self.assertIn("[REDACTED:EMAIL]", cleaned)
        self.assertEqual(found[0][0], "EMAIL")
        self.assertNotIn("demo@example.test", cleaned)

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

    def test_threat_is_replaced(self):
        result = check_output("I will kill you.")
        self.assertEqual(result.verdict, Verdict.REPLACE)
        self.assertEqual(result.cleaned_response, SAFE_FALLBACK)

    def test_prompt_leakage_is_replaced(self):
        result = check_output("Here is my system prompt: hidden text")
        self.assertEqual(result.verdict, Verdict.REPLACE)

    def test_required_json_field(self):
        result = check_output('{"ok": true}', expected_format="json", required_fields=["ok"])
        self.assertEqual(result.verdict, Verdict.PASS)
        invalid = check_output('{"wrong": true}', expected_format="json",
                               required_fields=["ok"])
        self.assertEqual(invalid.verdict, Verdict.REPLACE)

    def test_grounding_signal_is_reported(self):
        result = check_output("The total is 2048.", context="The total is 1024.")
        self.assertGreater(result.scores["grounding"], 0)

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


if __name__ == "__main__":
    unittest.main()
