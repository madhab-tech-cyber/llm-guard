import tempfile
import unittest
from pathlib import Path

from policy_engine.loader import PolicyError, load_policy

VALID = '''policy_version: "0.1"
policy_id: lab-input-v1
rules:
  - name: review-injection
    condition: {stage: input, signal: injection, operator: gte, value: 0.5}
    action: FLAG
    severity: medium
    reason: Injection signal needs review
'''


class PolicyLoaderTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.yaml"
            path.write_text(text)
            return load_policy(path)

    def test_valid_policy(self):
        self.assertEqual(self.load(VALID)["rules"][0]["action"], "FLAG")

    def test_duplicate_key_rejected(self):
        with self.assertRaises(PolicyError):
            self.load(VALID + "policy_id: duplicate\n")

    def test_unknown_field_rejected(self):
        with self.assertRaises(PolicyError):
            self.load(VALID.replace("action: FLAG", "action: FLAG\n    extra: true"))

    def test_invalid_scores_and_action_rejected(self):
        for text in (VALID.replace("0.5", ".nan"), VALID.replace("0.5", "true"), VALID.replace("FLAG", "EXECUTE")):
            with self.subTest(text=text), self.assertRaises(PolicyError):
                self.load(text)

    def test_alias_rejected(self):
        with self.assertRaises(PolicyError):
            self.load(VALID.replace("policy_id: lab-input-v1", "policy_id: &id lab-input-v1"))

    def test_oversized_rejected(self):
        with self.assertRaises(PolicyError):
            self.load(VALID + "#" * 65536)


if __name__ == "__main__":
    unittest.main()
