# Member 3 — Output Guard

Checks generated model responses before release and returns a verdict, cleaned response, reasons, confidence scores, findings and per-checker timings.

## Quick start

    python -m unittest scanners.output_guard.test_output_guard -v
    python -m unittest scanners.output_guard.test_pipeline_contract -v
    python -m scanners.output_guard.evaluate

The deterministic evaluation generates 200 synthetic cases (40 each for clean, PII, threat, prompt-leakage and malformed JSON). Its precision/recall/F1 values measure only those authored patterns, not real-world performance.

## Pipeline adapter

`pipeline_contract.py` exposes `OutputGuardRequest` and `inspect_output`. It maps PASS → clean, REDACT → suspicious, and BLOCK/REPLACE → blocked, using the common response field style proposed in Member 2's Day 5 document. Blocked output has an empty `masked_output`.

**The Member 2 interface is still marked pending Member 1 sign-off.** This adapter is a proposal for review, not a claim that the cross-team contract is approved. See `PIPELINE_CONTRACT.md`.

## Checker scope and limitations

- PII: regex heuristics for email, phone, PAN (with context) and IPv4; not exhaustive.
- Toxicity: transparent rules for a small set of threat/abuse patterns; not a trained moderation model.
- Format: standard-library JSON syntax and required top-level fields; not full JSON Schema.
- Prompt leakage: explicit disclosure phrases only; paraphrases and encoded disclosures may evade it.
- Grounding: lexical signal for selected names/numbers absent from context; cannot prove truth.
- Streaming: buffers the full answer and releases nothing until final validation.

Checker failures fail closed. Reasons contain finding types, not raw PII values. Use synthetic data only; do not log raw private text.
