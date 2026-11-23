# Member 4 policy engine (lab)

Day 6 provides a standalone strict YAML loader. The Member 1–3 signal interface is still under review; no runtime decision or enforcement is implemented here yet.

Install `policy-engine/requirements.txt` in an isolated Python environment, then run `python -m unittest discover -s tests -p 'test_policy_loader.py'`. `policy_engine.loader.load_policy(path)` returns a validated policy dictionary or raises `PolicyError`. Files are limited to 64 KiB and 100 rules. Unknown fields, duplicate keys, YAML anchors/aliases, invalid scores and unknown actions are rejected.

Day 7 adds `matching_rules(policy, stage, scores)`. It returns matching rules in policy order and rejects missing or invalid required scores. It does not make a final decision; that is Day 8. Run all current tests with `python -m unittest discover -s tests -p "test_policy_*.py"`.

Days 8–9 add standalone `decide(...)` and `AuditWriter`. Decisions use the first matching rule after validation, with a clean default ALLOW; blocked guard results and invalid context take BLOCK. The audit writer appends minimized JSONL records with fsync. Audit failure returns BLOCK with `audit_ok=False`. FLAG delivery and the cross-member signal adapter still need team agreement.

Day 10–11 standalone use:

```python
from policy_engine import AuditWriter, decide, load_policy
policy = load_policy("policy-engine/examples/lab-policy.yaml")
result = decide(policy=policy, request_id="synthetic_1", stage="input",
                verdict="clean", scores={"injection": 0.01},
                masked_available=False, audit=AuditWriter("audit.jsonl"))
```

The example is synthetic and uses draft score names. An actual pipeline adapter, verified mask provenance and FLAG delivery semantics require Member 1–3 agreement. The audit file contains only bounded identifiers and static reason codes. Run `python -m unittest discover -s tests -p 'test_policy_*.py'` after installing `policy-engine/requirements.txt`.

Days 16–17 select the highest severity among matching rules (`critical > high > medium > low`); ties choose the stricter action (`BLOCK > REDACT > FLAG > ALLOW`), then preserve file order. `risk_score` returns the maximum validated detector score for the stage. These are standalone lab semantics pending team agreement.
