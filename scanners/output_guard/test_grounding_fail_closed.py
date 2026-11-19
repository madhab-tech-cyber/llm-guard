"""Regression tests for output guard fail-closed behavior."""
import unittest

from scanners.output_guard.output_guard import SAFE_FALLBACK, Verdict, check_output


class TestGroundingFailClosed(unittest.TestCase):
    def test_unsupported_numeric_claim_is_replaced(self):
        result = check_output(
            "The measured value is 2048.",
            context="The measured value is 1024.",
        )
        self.assertEqual(result.verdict, Verdict.REPLACE)
        self.assertEqual(result.cleaned_response, SAFE_FALLBACK)
        self.assertEqual(result.findings[-1].checker, "grounding")

    def test_supported_claim_passes(self):
        result = check_output(
            "The measured value is 1024.",
            context="The measured value is 1024.",
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_grounding_disabled_without_context(self):
        result = check_output("The measured value is 2048.")
        self.assertEqual(result.verdict, Verdict.PASS)
        self.assertEqual(result.scores["grounding"], 0.0)


if __name__ == "__main__":
    unittest.main()
