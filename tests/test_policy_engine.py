import json
import tempfile
import unittest
from pathlib import Path

from policy_engine.audit import AuditWriter
from policy_engine.engine import decide


def policy(action="FLAG"):
    return {"policy_version": "0.1", "policy_id": "lab", "rules": [
        {"name": "high-injection", "condition": {"stage": "input", "signal": "injection", "operator": "gte", "value": 0.8},
         "action": action, "severity": "high", "reason": "Synthetic match"}]}


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.jsonl"
        self.audit = AuditWriter(self.path)

    def run_decision(self, **kwargs):
        args = dict(policy=policy(), request_id="req_1", stage="input", verdict="clean",
                    scores={"injection": 0.1}, masked_available=False, audit=self.audit)
        args.update(kwargs)
        return decide(**args)

    def test_clean_default_and_first_match_audited(self):
        self.assertEqual(self.run_decision().action, "ALLOW")
        self.assertEqual(self.run_decision(scores={"injection": 0.9}).action, "FLAG")
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual([row["decision"] for row in rows], ["ALLOW", "FLAG"])
        self.assertEqual(rows[1]["rule_id"], "high-injection")
        self.assertEqual(set(rows[0]), {"time_utc", "request_id", "stage", "decision", "policy_version", "reason_code", "rule_id"})

    def test_guard_block_overrides_allow_rule(self):
        self.assertEqual(self.run_decision(policy=policy("ALLOW"), verdict="blocked", scores={"injection": 0.9}).action, "BLOCK")

    def test_redact_requires_verified_mask(self):
        self.assertEqual(self.run_decision(policy=policy("REDACT"), scores={"injection": 0.9}).reason_code, "MASK_UNAVAILABLE")
        self.assertEqual(self.run_decision(policy=policy("REDACT"), scores={"injection": 0.9}, masked_available=True).action, "REDACT")

    def test_bad_signal_or_audit_failure_blocks(self):
        self.assertEqual(self.run_decision(scores={}).action, "BLOCK")
        missing = AuditWriter(Path(self.temp.name) / "missing" / "audit.jsonl")
        result = self.run_decision(audit=missing)
        self.assertEqual((result.action, result.audit_ok), ("BLOCK", False))


if __name__ == "__main__":
    unittest.main()
