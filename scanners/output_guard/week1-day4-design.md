# Week 1 — Day 4: Output Guard design v1

## Purpose

Inspect generated model output before it is released. Return a verdict, cleaned response, reasons, scores, type-only findings and checker timings.

## Processing order

1. Validate input and policy configuration.
2. Detect and mask recognised PII (email, phone, Aadhaar, PAN, card and IP).
3. Detect known secret formats (cloud/API keys, GitHub/Stripe tokens, JWTs, private-key headers, passwords, database credentials and webhooks). A secret signal replaces the whole answer with \`SAFE_FALLBACK\`.
4. Check toxicity and explicit prompt-leakage patterns.
5. Validate JSON syntax and required fields when requested.
6. Compare selected numeric/date/name tokens with supplied context. One unsupported number/date is a strong signal (0.75); an isolated capitalised word remains below the 0.75 replacement threshold.
7. Any checker exception returns \`REPLACE\` with \`SAFE_FALLBACK\`.

## Verdict policy

- \`PASS\`: no high-confidence safety signal.
- \`REDACT\`: PII found and safely masked.
- \`BLOCK\`: PII policy explicitly requests dropping the output.
- \`REPLACE\`: detected secret, toxicity, prompt leakage, invalid required format, strong unsupported grounding signal, or checker failure.

The pipeline adapter's verdict mapping is intentionally unchanged.

## Grounding limits

Grounding is lexical comparison against supplied context. It can flag selected unsupported claims but cannot prove an answer is true. It may miss paraphrases, inference, semantic contradictions and unsupported claims expressed without candidate tokens.

## Evaluation

Keep the existing 200-case synthetic corpus and add a separate 40-case grounding set: 20 supported numeric claims and 20 deliberately unsupported numeric claims, each with explicit context. Report TP/FP/TN/FN, precision, recall and F1 for grounding as well as the other checkers. Synthetic pattern coverage only; these numbers are not production accuracy.

## Privacy and lab boundary

Use fake values only. Findings and reasons name the detected type, never the matched PII or secret. Do not log or persist raw values. The guard is a heuristic layer, not a complete DLP or moderation system.
