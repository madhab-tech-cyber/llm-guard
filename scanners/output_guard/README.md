# Member 3 — Output Guard

Checks generated model responses before release and returns a verdict, cleaned response, reasons, confidence scores, findings and per-checker timings.

## Quick start

Run from the repository root:

    python -m unittest scanners.output_guard.test_output_guard -v

Run the deterministic synthetic evaluation:

    python -m scanners.output_guard.evaluate

The evaluation generates 200 cases (40 each for clean, PII, threat, prompt-leakage and malformed JSON) and reports per-checker precision, recall and F1. These are synthetic pattern-coverage metrics only, not estimates of real-world performance.

The package entry point is scanners.output_guard.check_output.

## Verdicts

- PASS: no configured checker found a release-blocking issue.
- REDACT: PII was masked or grounding signals need review.
- BLOCK: reserved for a policy decision to suppress content.
- REPLACE: replace the unsafe answer with a fixed safe fallback.

The initial orchestrator emits PASS, REDACT and REPLACE.

## Checker scope and limitations

- PII: regex heuristics for email, phone, PAN (with context) and IPv4; not exhaustive.
- Toxicity: transparent rules for a small set of threat/abuse patterns; not a trained moderation model.
- Format: standard-library JSON syntax and required top-level fields; not full JSON Schema.
- Prompt leakage: detects explicit disclosure phrases; paraphrases and encoded disclosures may evade it.
- Grounding: flags numbers, dates and capitalised tokens absent from context. It cannot prove truth or detect every hallucination.
- Streaming: buffers the complete answer and releases nothing until final validation. This trades latency for safer chunk-boundary handling.

Checker failures fail closed and return a safe fallback. Reasons contain finding types, not raw PII values. Use synthetic data only in this lab. Do not log raw private text.
