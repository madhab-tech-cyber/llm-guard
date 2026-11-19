"""Tests for the Member 3 pipeline-facing adapter."""
import unittest

from scanners.output_guard.pipeline_contract import OutputGuardRequest, inspect_output


class TestPipelineContract(unittest.TestCase):
    def test_clean_maps_to_clean(self):
        result = inspect_output(OutputGuardRequest("A safe explanation.", "model", 1))
        self.assertEqual(result.verdict, "clean")
        self.assertEqual(result.masked_output, "A safe explanation.")
        self.assertIn("pii", result.scores)

    def test_pii_maps_to_suspicious_and_masks(self):
        result = inspect_output(OutputGuardRequest(
            "Contact demo@example.test", "model", 2
        ))
        self.assertEqual(result.verdict, "suspicious")
        self.assertNotIn("demo@example.test", result.masked_output)
        self.assertIn("detector_timings_ms", result.to_dict())

    def test_blocked_output_is_never_forwarded(self):
        result = inspect_output(OutputGuardRequest(
            "I will kill you.", "model", 1
        ))
        self.assertEqual(result.verdict, "blocked")
        self.assertEqual(result.masked_output, "")

    def test_missing_source_fails_closed(self):
        result = inspect_output(OutputGuardRequest("safe text", "", 1))
        self.assertEqual(result.verdict, "blocked")
        self.assertEqual(result.masked_output, "")

    def test_invalid_turn_fails_closed(self):
        result = inspect_output(OutputGuardRequest("safe text", "model", 0))
        self.assertEqual(result.verdict, "blocked")


if __name__ == "__main__":
    unittest.main()
