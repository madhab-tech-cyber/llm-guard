# Policy engine design v1 — Member 4 Day 4

Date: 17 November 2026. Synthetic lab design; no runtime or approval is implied.

## Purpose and boundary

Member 1 calls this module before the LLM request and after the LLM reply. Members 2 and 3 supply detector signals. The policy engine validates those signals against a versioned YAML policy and returns one `ALLOW`, `BLOCK`, `REDACT`, or `FLAG` decision with safe reason codes and matching rule IDs. Member 1 remains responsible for whether any content is forwarded. Member 5 consumes minimized audit/export data.

## Components

1. **Loader and validator:** parse a bounded YAML file, reject duplicate keys, unknown fields, invalid score ranges, invalid actions, duplicate rule names and unknown version. Compile rules into an immutable in-memory set. Never use `yaml.load` with arbitrary object construction.
2. **Signal adapter:** accept only the reviewed Member 2/3 signal envelopes. Validate stage, request ID, detector status, score names and finite numeric values. Treat a missing required signal as an error.
3. **Matcher and decision engine:** evaluate ordered rules against category labels and detector scores. Day 8 starts with first-match behavior. A guard `blocked` verdict and any internal failure take the BLOCK path before ordinary rules. Day 16 will add explicit priorities/conflict resolution.
4. **Audit writer:** append one minimized JSON line for each evaluated decision: UTC time, opaque request ID, stage, policy version, decision, static reason code and rule IDs. No raw prompt/reply, secret, personal identifier or unmasked finding text. An append failure is visible and blocks release of content.
5. **Later controls:** rate caps and quotas (Days 19/21), hot reload (Day 36), query/export (Days 34/37), and hash-chain integrity (Day 46).

## Decision contract draft

Input: `request_id`, `stage`, validated guard verdict, detector status, stage-specific scores and category labels, and whether a verified masked artifact is available. Output: `request_id`, `stage`, `policy_version`, `decision`, `reason_code`, `matched_rule_ids`, `audit_status`. A REDACT decision never generates or certifies masked content; it requires Member 2/3 to provide a verified mask for the same request and stage. FLAG delivery semantics must be agreed with Member 1 before integration.

## Failure behavior

Invalid policy, malformed or absent signal, detector timeout, missing context, or audit append failure means BLOCK. The caller receives a bounded error code. Logs must exclude raw content and error payloads that may contain secrets. A policy cannot turn an internal failure into ALLOW. The Day 8 clean default ALLOW applies only after complete validation.

## Test and evidence plan

- Day 6: malformed and oversized YAML rejection.
- Days 7–11: each decision path, rule matching and guard-failure cases.
- Day 13: fifty synthetic labelled cases, with raw counts.
- Day 25: ten prompt/reply pairs through Member 1's pipeline, if available.
- Day 29: isolated policy decision latency with hardware, sample count and percentiles; distinguish it from full pipeline latency.

The Day 2 language draft and Day 3 decision model define details. Day 5 requires actual agreement on the interface before implementation claims cross-member compatibility.
