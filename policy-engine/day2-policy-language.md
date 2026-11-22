# Member 4 — Day 2 YAML policy language draft

Date: 16 November 2026. This is a design draft for synthetic lab data. It is not an approved interface or executable policy.

## Proposed document shape

```yaml
policy_version: "0.1"
policy_id: "lab-input-v1"
rules:
  - name: "block-known-secret"
    condition:
      stage: input
      signal: secrets
      operator: gte
      value: 0.90
    action: BLOCK
    severity: critical
    reason: "Secret detector crossed the lab threshold"
  - name: "review-injection"
    condition:
      stage: input
      signal: injection
      operator: gte
      value: 0.50
    action: FLAG
    severity: medium
    reason: "Injection signal needs review"
```

The example thresholds are placeholders for tests, not team-approved operating limits. No raw prompt, reply, identifier, credential, or key belongs in this file. Secrets must come from the runtime environment.

## Fields and constraints for the Day 6 validator

| Field | Required | Validation |
| --- | --- | --- |
| `policy_version` | Yes | Nonempty version string; reject unknown major versions. |
| `policy_id` | Yes | Unique stable identifier, 1–64 ASCII letters, digits, `_` or `-`. |
| `rules` | Yes | Nonempty list, bounded to 100 entries in v0.1. |
| `name` | Yes | Unique rule name, 1–64 safe ASCII characters. |
| `condition.stage` | Yes | `input` or `output`. |
| `condition.signal` | Yes | Name from the agreed detector signal registry. Unknown names fail validation. |
| `condition.operator` | Yes | `gte` or `lte` for numeric scores in v0.1. |
| `condition.value` | Yes | Finite number from 0.0 to 1.0 inclusive; reject NaN, infinity and strings. |
| `action` | Yes | Exactly `ALLOW`, `BLOCK`, `REDACT`, or `FLAG`. |
| `severity` | Yes | `low`, `medium`, `high`, or `critical`. |
| `reason` | Yes | Short safe static text, 1–160 characters; never copy user content into it. |

Reject duplicate YAML keys, unknown fields, duplicate names, missing values, malformed YAML, oversized files, and invalid signal or action names. A bad policy must produce a bounded validation error and must never silently load. The Day 8 draft first-match behavior depends on file order; explicit priorities and conflict handling arrive on Day 16.

## Interface dependency

Member 2's Day 5 interface draft proposes `verdict`, `reasons`, `scores`, and `masked_prompt`, with score keys `injection`, `jailbreak_encoding`, `pii`, `secrets`, `limits`, and `sanitizer`. Member 1 has not signed that draft. This language uses one proposed `scores` key at a time and will be revised after Members 1–3 agree on input and output signal shapes. `REDACT` will require an already verified safe masked value; the policy engine must not invent a redaction.

## Day 2 evidence

The field schema, two sample rules, and rejection rules are recorded here. Day 6 will implement and test the loader. No parser, runtime decision, or team sign-off is claimed yet.
