"""Standalone output guard handoff; no pipeline release authorization."""

import tempfile
import unittest
from pathlib import Path

from policy_engine import AuditWriter, decide, load_policy
from scanners.output_guard.pipeline_contract import OutputGuardRequest, inspect_output


class OutputHandoffTests(unittest.TestCase):
    def test_clean_output_score_shape_is_accepted(self):
        guard = inspect_output(OutputGuardRequest(output_text="A short factual reply.",
                                                   source="model", turn_number=1))
        policy = load_policy("policy-engine/examples/lab-policy.yaml")
        with tempfile.TemporaryDirectory() as tmp:
            result = decide(policy=policy, request_id="synthetic_output", stage="output",
                            verdict=guard.verdict, scores=guard.scores,
                            masked_available=False, audit=AuditWriter(Path(tmp) / "audit.jsonl"))
        self.assertEqual(result.action, "ALLOW")
        self.assertTrue(result.audit_ok)
