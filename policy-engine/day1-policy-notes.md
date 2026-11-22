# Member 4 — Day 1 policy model notes

Start date: 13 November 2026. Lab policies and synthetic inputs only. These are design examples, not approved runtime rules.

## Models considered

| Model | Use | Limitation |
| --- | --- | --- |
| Allow list | Permit known routes, model providers, and service identities | Needs maintenance; unknown traffic needs a defined default |
| Deny list | Reject known malicious patterns and prohibited destinations | Misses novel wording and evasions |
| Ordered rules | Match detector signals and context, then choose an action with a reason | Conflicts need explicit priority (Day 16) |
| Risk score | Combine independent input/output signals for review thresholds | Scores require calibration; never turn a raw score into an unexplained block |

The initial decision set is ALLOW, BLOCK, REDACT, and FLAG. A rule should name its condition, action, severity, and reason. Missing or invalid required signals must be treated as an error and blocked with an audit record once the engine exists. These notes do not set production thresholds.

## Ten example policies to develop and test

| ID | Example condition | Proposed action | Why |
| --- | --- | --- | --- |
| P01 | Input guard reports a direct instruction to ignore system rules | BLOCK | Prompt injection |
| P02 | Retrieved document contains instructions aimed at the assistant | FLAG | Indirect injection needs review context |
| P03 | Multi-turn request attempts to override a prior refusal | FLAG | Possible conversation-based jailbreak |
| P04 | Encoded or obfuscated instructions are detected | FLAG | Require decoded inspection before a stronger action |
| P05 | Input requests secrets, credentials, or private keys | BLOCK | Prevent secret extraction |
| P06 | Input includes a recognized personal identifier needed for a permitted task | REDACT | Minimize exposed data |
| P07 | Output guard finds a credential or API key in a reply | BLOCK | Avoid releasing secrets |
| P08 | Output guard finds personal data in a reply that can be safely masked | REDACT | Protect sensitive fields |
| P09 | Output guard reports harmful or abusive content above an agreed threshold | FLAG | Human review until thresholds are validated |
| P10 | No detector flags and the request is within approved limits | ALLOW | Normal lab request |

These are distinct test cases, not a fixed default policy set. Member 1 must agree on the decision interface, and Members 2 and 3 must agree on signal names and meanings by Day 5. Rate limits, conflict priorities, and numeric risk thresholds belong to later days in the plan.

## Day 1 evidence and next step

The ten examples above include direct, indirect, multi-turn, encoding, and secret-extraction cases aligned with Member 2's Day 1 attack examples. Day 2 will define the YAML fields and validation rules. No code, decision timing, or team sign-off is claimed today.
