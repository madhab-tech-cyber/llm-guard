"""Tests for grounding metrics in the synthetic evaluation."""
import unittest

from scanners.output_guard.evaluate import build_grounding_cases, evaluate


class TestGroundingEvaluation(unittest.TestCase):
    def test_grounding_corpus_has_supported_and_unsupported_claims(self):
        cases = build_grounding_cases()
        self.assertEqual(len(cases), 40)
        self.assertEqual(sum(case.unsupported for case in cases), 20)
        self.assertTrue(all(case.context for case in cases))

    def test_evaluation_reports_grounding_precision_and_recall(self):
        report = evaluate()
        grounding = report["metrics"]["grounding"]
        self.assertEqual(report["total_cases"], 200)
        self.assertEqual(report["grounding_cases"], 40)
        self.assertEqual(grounding["tp"], 20)
        self.assertEqual(grounding["fn"], 0)
        self.assertEqual(grounding["fp"], 0)
        self.assertEqual(grounding["tn"], 20)
        self.assertEqual(grounding["precision"], 1.0)
        self.assertEqual(grounding["recall"], 1.0)
        self.assertIn("Synthetic pattern coverage only", report["limitations"])


if __name__ == "__main__":
    unittest.main()
