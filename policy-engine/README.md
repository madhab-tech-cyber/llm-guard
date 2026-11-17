# Member 4 policy engine (lab)

Day 6 provides a standalone strict YAML loader. The Member 1–3 signal interface is still under review; no runtime decision or enforcement is implemented here yet.

Install `policy-engine/requirements.txt` in an isolated Python environment, then run `python -m unittest discover -s tests -p 'test_policy_loader.py'`. `policy_engine.loader.load_policy(path)` returns a validated policy dictionary or raises `PolicyError`. Files are limited to 64 KiB and 100 rules. Unknown fields, duplicate keys, YAML anchors/aliases, invalid scores and unknown actions are rejected.
