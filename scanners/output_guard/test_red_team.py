"""Tests for the safe synthetic Output Guard red-team corpus."""
import unittest
from scanners.output_guard.red_team import build_red_team_cases, evaluate_red_team

class TestOutputGuardRedTeam(unittest.TestCase):
    def test_corpus_has_30_unique_cases_and_expected_groups(self):
        cases = build_red_team_cases()
        self.assertEqual(len(cases), 30)
        self.assertEqual(len({case.case_id for case in cases}), 30)
        self.assertEqual(
            {category: sum(case.category == category for case in cases)
             for category in ("pii", "toxicity", "prompt_leakage", "format", "benign")},
            {"pii": 6, "toxicity": 6, "prompt_leakage": 6, "format": 6, "benign": 6},
        )

    def test_report_tracks_expected_misses_and_benign_flags(self):
        report = evaluate_red_team()
        self.assertEqual(report["total_cases"], 30)
        self.assertIn("benign_false_positives", report)
        self.assertIn("expected_pattern_misses", report)
        self.assertEqual(len(report["cases"]), 30)
        self.assertIn("synthetic", report["limitations"].lower())

if __name__ == "__main__":
    unittest.main()
