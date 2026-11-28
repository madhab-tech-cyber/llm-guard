"""Hundred-case Member 2 guard handoff invariants; not accuracy evaluation."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from policy_engine import AuditWriter, decide, load_policy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanners" / "input-guard"))
from input_guard import check_prompt  # noqa: E402


class HundredCaseHandoffTests(unittest.TestCase):
    def test_hundred_synthetic_cases(self):
        items = json.loads((ROOT / "scanners" / "input-guard" /
                            "day12_test_set.json").read_text())["items"]
        self.assertEqual(len(items), 100)
        policy = load_policy(ROOT / "policy-engine" / "examples" / "lab-policy.yaml")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            for item in items:
                guard = check_prompt(item["prompt"], mode="heuristics")
                result = decide(policy=policy, request_id="case_" + item["id"],
                                stage="input", verdict=guard["verdict"],
                                scores=guard["scores"], masked_available=False,
                                audit=AuditWriter(path))
                self.assertTrue(result.audit_ok, item["id"])
                if guard["verdict"] == "blocked":
                    self.assertEqual(result.action, "BLOCK", item["id"])
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 100)
            self.assertTrue(all("prompt" not in row and "reasons" not in row for row in rows))
