# Member 4 policy engine (lab)

Standalone policy loader, matcher, decision engine, masked audit writer and process-local quota. The Member 1–3 signal interface remains a draft; this module is not wired into the proxy and does not enforce traffic.

## Install and test

In an isolated Python environment, install `policy-engine/requirements.txt`, then run from the repository root:

```sh
python3 -m unittest discover -s tests -p 'test_policy*.py' -q
```

## Standalone call

```python
from policy_engine import AuditWriter, RateLimiter, decide, load_policy
policy = load_policy("policy-engine/examples/lab-policy.yaml")
quota = RateLimiter(limit=10, window_seconds=60)
result = decide(policy=policy, request_id="synthetic_1", stage="input",
                verdict="clean", scores={"injection": 0.01},
                masked_available=False, audit=AuditWriter("audit.jsonl"),
                quota=quota, caller_id="lab-caller")
```

`load_policy(path)` validates a YAML file of at most 64 KiB and 100 rules; invalid files raise `PolicyError`. `decide` returns `Decision(action, reason_code, rule_id, audit_ok)`. It validates detector scores, selects the highest severity matching rule, uses stricter action for severity ties, and returns `BLOCK` for invalid context, missing verified masking, quota denial or unavailable audit. `FLAG` delivery semantics remain unapproved.

`RateLimiter` is optional and process-local. An invalid caller key, quota exhaustion, clock regression or full key table denies. It does not provide distributed or durable limits. The quota key must be an opaque ID, not a user email or prompt text. Each decision attempts a minimized JSONL audit append with UTC time, opaque request ID, stage, action, policy version, static reason code and selected rule ID. Configure the path explicitly; do not store raw prompt, reply or scanner reasons.

Member 1–3 input mappings, verified mask provenance and delivery semantics need cross-member sign-off. Member 5 may run the standalone synthetic harness today; CSV/JSON export and a production adapter are planned.

Day 22 fail-closed regressions cover invalid verdicts, non-finite scores, missing verified masks, quota denial and unavailable audit. Day 23 adds `load_config(path)` for a small strict JSON lab configuration (example: `policy-engine/examples/lab-config.json`). It requires an explicit audit path and bounded quota settings. This is local configuration, not a deployment manifest or a shared service contract.
