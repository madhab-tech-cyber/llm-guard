"""Tests for the deterministic evaluation and target calculations."""
import unittest

from scanners.output_guard.evaluate import build_cases, evaluate


class TestEvaluation(unittest.TestCase):
    def test_dataset_contains_200_balanced_cases(self):
        cases = build_cases()
        self.assertEqual(len(cases), 200)
        counts = {category: sum(case.category == category for case in cases)
                  for category in ("clean", "pii", "toxicity", "prompt_leakage", "format")}
        self.assertEqual(counts, {
            "clean": 40,
            "pii": 40,
            "toxicity": 40,
            "prompt_leakage": 40,
            "format": 40,
        })

    def test_report_contains_detection_and_performance_metrics(self):
        report = evaluate()
        self.assertEqual(report["total_cases"], 200)
        self.assertEqual(report["aggregate"]["bad_outputs"], 160)
        self.assertEqual(report["aggregate"]["good_outputs"], 40)
        self.assertIn("p95_ms", report["performance"])
        self.assertIn("bad_outputs_caught_at_least_90_percent", report["targets"])
        self.assertIn("good_outputs_blocked_at_most_5_percent", report["targets"])
        self.assertIn("p95_check_latency_under_100_ms", report["targets"])
        self.assertIn("synthetic", report["limitations"].lower())


if __name__ == "__main__":
    unittest.main()
