# Member 4 interface review — Day 5

Prepared 17 November 2026. Status: **proposed; no Member 1, 2 or 3 sign-off recorded**.

## Proposed handoff

| Partner | Needed input or output | Current status |
| --- | --- | --- |
| Member 1 | Supplies a stable opaque request ID, stage, validated guard result and verified masked artifact reference; consumes decision, safe reason code and audit outcome. Defines whether FLAG holds delivery. | Awaiting review of the call points and failure semantics. |
| Member 2 | Input guard result with `clean/suspicious/blocked`, six proposed 0–1 score names, category labels and verified mask availability. | Member 2's `scanners/input-guard/day5-interface-agreement.md` is a draft pending Member 1 sign-off. Its raw `reasons` and `masked_prompt` must not enter policy audit records. |
| Member 3 | Output guard result with the same required semantics after stage-specific mapping, including secret/PII categories and a verified mask marker. | Output schema and failure representation not yet available in the inspected branch. |
| Member 5 | Receives minimized decision and audit fields, later CSV/JSON export. | Query/export shape to agree before Days 34/37. |

## Questions requiring team decisions

1. Does Member 1 call the engine twice under the same request ID, with distinct input and output stage IDs?
2. Are Member 2's six score names final, and which are mandatory even when zero?
3. What exact Member 3 fields represent output risk, safe masking and detector failure?
4. Does FLAG hold content for review or allow labelled delivery? It must not be assumed.
5. Which component owns the write acknowledgement for an audit record before delivery?

Until these answers are recorded, Days 6–10 may implement only a standalone adapter against a clearly labelled draft contract. This note records a review request to make with teammates; it does not claim that they accepted it.
