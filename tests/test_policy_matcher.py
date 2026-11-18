import unittest

from policy_engine.loader import PolicyError
from policy_engine.matcher import matching_rules

POLICY = {
    "policy_version": "0.1", "policy_id": "lab",
    "rules": [
        {"name": "input-review", "condition": {"stage": "input", "signal": "injection", "operator": "gte", "value": 0.5}, "action": "FLAG", "severity": "medium", "reason": "Review injection"},
        {"name": "input-block", "condition": {"stage": "input", "signal": "injection", "operator": "gte", "value": 0.9}, "action": "BLOCK", "severity": "high", "reason": "Block injection"},
        {"name": "output-secret", "condition": {"stage": "output", "signal": "secrets", "operator": "gte", "value": 0.8}, "action": "BLOCK", "severity": "critical", "reason": "Block secret"},
    ],
}


class MatcherTests(unittest.TestCase):
    def test_input_thresholds_and_order(self):
        self.assertEqual([r["name"] for r in matching_rules(POLICY, "input", {"injection": 0.9})], ["input-review", "input-block"])
        self.assertEqual(matching_rules(POLICY, "input", {"injection": 0.49}), [])

    def test_output_stage_isolated(self):
        self.assertEqual([r["name"] for r in matching_rules(POLICY, "output", {"secrets": 0.8})], ["output-secret"])

    def test_missing_invalid_and_unknown_scores_rejected(self):
        for stage, scores in (("input", {"secrets": 0.5}), ("input", {"injection": float("nan")}), ("input", {"injection": True}), ("input", {"unknown": 0.9}), ("other", {"injection": 0.9})):
            with self.subTest(stage=stage, scores=scores), self.assertRaises(PolicyError):
                matching_rules(POLICY, stage, scores)


if __name__ == "__main__":
    unittest.main()
