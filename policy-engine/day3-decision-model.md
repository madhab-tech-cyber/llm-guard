# Member 4 — Day 3 decision model draft

Completed 16 November 2026, ahead of the numbered-day cadence. Synthetic lab design only; Members 1–3 have not approved this interface.

## Boundary and flow

```text
Input Guard (M2) signals ──┐
                           ├── validate stage + signals ── evaluate policy ── one decision + reason ── audit
Output Guard (M3) signals ─┘                                      │
                                                    ALLOW / BLOCK / REDACT / FLAG
```

Member 1 calls the policy engine once before sending a prompt to the model and once before releasing a model reply. The decision must identify the stage (`input` or `output`) and request ID supplied by the pipeline. The engine does not create a request ID from detector scores or content. No raw prompt or reply is needed for rule matching.

## Proposed signal envelope

| Field | Meaning |
| --- | --- |
| `request_id` | Opaque stable ID from Member 1; required for audit linkage. |
| `stage` | `input` or `output`; required. |
| `verdict` | Stage guard's `clean`, `suspicious`, or `blocked` result; proposed for both guards, pending Member 3 agreement. |
| `scores` | Named finite values from 0.0 to 1.0; names must be in the agreed stage registry. |
| `findings` | Safe category labels such as `pii:email` or `secret:api_key`; never raw matched text. |
| `masked_available` | True only when that guard produced a verified safe masked artifact for this request and stage. |
| `detector_status` | `ok`, `timeout`, or `error`; failure is never treated as a low risk score. |

Member 2's current draft exposes `verdict`, `scores`, `reasons`, and `masked_prompt`, with six proposed score names. It has not been signed by Member 1. Member 3's output shape is still needed. An adapter may translate each guard's reviewed result into this envelope only after the team accepts the mapping; it must not trust unvalidated client-supplied scores.

## Decision rules, in order

1. Missing, malformed, stale, or mismatched required context; detector failure; policy load or audit failure: `BLOCK` with a bounded internal reason code. The audit failure itself must be surfaced as a failure, not reported as successful logging.
2. A guard verdict of `blocked` or an applicable `BLOCK` rule: `BLOCK`. A later rule cannot override it.
3. An applicable `REDACT` rule: `REDACT` only when a guard has supplied a verified masked artifact for the same request and stage. Otherwise `BLOCK`.
4. An applicable `FLAG` rule or a `suspicious` guard verdict: `FLAG` for review. The pipeline must define whether flagged content is held or shown before integration; no forwarding is implied here.
5. An applicable `ALLOW` rule or no matched rule with clean, complete signals: `ALLOW`, with a reason and audit record. The Day 8 engine's default ALLOW applies only after the preceding validation and failure checks.

This ordering is a safety proposal, not Day 16 priority logic. Multiple matching rules must all be recorded as safe rule IDs; the chosen action and reason must be deterministic. Threshold values and exact category mappings await Day 5 interface agreement.

## Examples for later tests

| Input signals | Expected result | Reason |
| --- | --- | --- |
| Input clean, all fields valid, no rule matches | ALLOW | Clean default path |
| Input blocked for injection | BLOCK | Guard block cannot be overridden |
| Input suspicious for PII, verified mask and REDACT rule | REDACT | Masked artifact available |
| Output secret finding, BLOCK rule | BLOCK | Prevent secret release |
| Output suspicious with no stronger rule | FLAG | Review path |
| Missing required score or output detector timeout | BLOCK | Fail closed |
| REDACT rule with no verified mask | BLOCK | No safe redacted artifact |

## Open decisions for Day 5

- Member 1: request ID, stage call points, audit failure handling, and FLAG delivery behavior.
- Member 2: final input score names, verdict semantics, finding categories, and masked artifact provenance.
- Member 3: output signal shape, safe mask proof, and what a detector failure reports.

No executable decision engine, audit log, or approved interface is claimed by this draft.
