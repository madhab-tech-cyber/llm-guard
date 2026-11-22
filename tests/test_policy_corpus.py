"""Self-labelled Day 13 engineering corpus, not independent accuracy evidence."""

import json
import tempfile
import unittest
from pathlib import Path

from policy_engine import AuditWriter, decide, load_policy

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests/fixtures/policy_cases_v1.json").read_text())


class CorpusTests(unittest.TestCase):
    def test_fifty_cases_and_audit(self):
        cases = CORPUS["cases"]
        self.assertEqual(len(cases), 50)
        counts = {action: 0 for action in ("ALLOW", "BLOCK", "REDACT", "FLAG")}
        with tempfile.TemporaryDirectory() as folder:
            audit_path = Path(folder) / "audit.jsonl"
            audit = AuditWriter(audit_path)
            for index, case in enumerate(cases):
                policy = load_policy(ROOT / "policy-engine/test-policies" / (case["policy"] + ".yaml"))
                scores = {} if case["score"] is None else {case["signal"]: case["score"]}
                result = decide(policy=policy, request_id=f"synthetic_{index}", stage=case["stage"],
                                verdict=case["verdict"], scores=scores,
                                masked_available=case["masked_available"], audit=audit)
                self.assertEqual(result.action, case["expected"], case)
                self.assertTrue(result.audit_ok, case)
                counts[result.action] += 1
            rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
        self.assertEqual(len(rows), 50)
        self.assertEqual(counts, {"ALLOW": 10, "BLOCK": 24, "REDACT": 2, "FLAG": 14})
        self.assertTrue(all(row["request_id"].startswith("synthetic_") for row in rows))


if __name__ == "__main__":
    unittest.main()
