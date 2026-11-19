# Member 3 — Output Guard pipeline adapter

**Status:** Adapter implementation for review; not a declaration that the Member 2 interface has received Member 1 sign-off.

## Purpose

Member 2's Day 5 proposal defines a common style: metadata in, one verdict, reasons, scores, a masked text field and per-checker timings out. The Output Guard uses the same response-field conventions while keeping output-specific names.

## Request

`OutputGuardRequest` accepts:
- `output_text`: generated model response to inspect.
- `source`: producer label (for example `model`).
- `turn_number`: positive conversation turn number.
- `context`: optional grounding context.
- `expected_format` and `required_fields`: optional output-format constraints.
- `pii_policy`: `mask` (default) or `drop`.

## Response

`OutputGuardResponse` returns the shared field pattern:
- `verdict`: `clean`, `suspicious` or `blocked`.
- `reasons`: human-readable finding summaries.
- `scores`: output checker scores.
- `masked_output`: safe-to-release text; empty for blocked output.
- `detector_timings_ms`: per-checker timings.

Mapping: internal PASS → clean; REDACT → suspicious; BLOCK/REPLACE → blocked. Blocked output is never forwarded. Missing source metadata and invalid turn numbers fail closed.

## Compatibility note

The Member 2 Day 5 document explicitly says it is pending Member 1 review and sign-off. This adapter is a reviewable proposal based on its field conventions. Member 1 should confirm naming, metadata requirements and verdict mapping before the teams call it an agreed interface.

## Test

    python -m unittest scanners.output_guard.test_pipeline_contract -v
