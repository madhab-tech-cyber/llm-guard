import json
import tempfile
import unittest
from pathlib import Path
from policy_engine.config import load_config
from policy_engine.loader import PolicyError


class ConfigTests(unittest.TestCase):
    def test_config_and_bounds(self):
        config = load_config("policy-engine/examples/lab-config.json")
        self.assertEqual(config.quota_limit, 10)
        self.assertTrue(config.quota().allow("lab", now=1))

    def test_invalid_config_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for value in ({"audit_path": "audit.jsonl"},
                          {"audit_path":"audit.jsonl", "quota_limit":False,
                           "quota_window_seconds":60, "quota_max_keys":10}):
                path.write_text(json.dumps(value))
                with self.assertRaises(PolicyError):
                    load_config(path)
