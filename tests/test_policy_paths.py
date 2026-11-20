"""Day 11 decision-path and audit boundary regressions."""

import json
import tempfile
import unittest
from pathlib import Path

from policy_engine import AuditWriter, decide, load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "policy-engine/examples/lab-policy.yaml"


class PolicyPathsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "audit.jsonl"
        self.audit = AuditWriter(self.path)
        self.policy = load_policy(EXAMPLE)

    def evaluate(self, stage, scores, verdict="clean", masked_available=False):
        return decide(policy=self.policy, request_id="synthetic_1", stage=stage,
                      verdict=verdict, scores=scores,
                      masked_available=masked_available, audit=self.audit)

    def test_all_four_actions_and_audit_rows(self):
        outcomes = [
            self.evaluate("input", {"injection": 0.01}),
            self.evaluate("input", {"injection": 0.95}),
            self.evaluate("output", {"pii": 0.8}, masked_available=True),
            self.evaluate("input", {"injection": 0.6}),
        ]
        self.assertEqual([d.action for d in outcomes], ["ALLOW", "BLOCK", "REDACT", "FLAG"])
        self.assertTrue(all(d.audit_ok for d in outcomes))
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual([r["decision"] for r in rows], ["ALLOW", "BLOCK", "REDACT", "FLAG"])
        self.assertTrue(all(set(r) == {"time_utc", "request_id", "stage", "decision", "policy_version", "reason_code", "rule_id"} for r in rows))

    def test_missing_required_score_blocks_and_audits(self):
        result = self.evaluate("input", {"pii": 0.0})
        self.assertEqual((result.action, result.reason_code), ("BLOCK", "INVALID_CONTEXT"))
        self.assertEqual(json.loads(self.path.read_text())["decision"], "BLOCK")

    def test_suspicious_without_match_flags(self):
        result = self.evaluate("input", {"injection": 0.1}, verdict="suspicious")
        self.assertEqual(result.action, "FLAG")

    def test_redact_without_mask_blocks(self):
        result = self.evaluate("output", {"pii": 0.8})
        self.assertEqual((result.action, result.reason_code), ("BLOCK", "MASK_UNAVAILABLE"))


if __name__ == "__main__":
    unittest.main()
