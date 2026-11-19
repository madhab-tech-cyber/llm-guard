# Week 1 — Day 3: Output Guard checklist

- [x] Define output risks: PII, secrets, toxicity, prompt leakage, format and grounding.
- [x] Keep all fixtures synthetic and use \`example.test\` for email domains.
- [x] Ensure PII findings contain type only, never the matched value.
- [x] Add Aadhaar Verhoeff and credit-card Luhn checks before masking.
- [x] Mask bare PAN-shaped identifiers without relying on surrounding context.
- [x] Detect common API-key / secret formats and replace secret-bearing output.
- [x] Keep unsupported numeric/date grounding signals above the replacement threshold.
- [x] Keep a supported numeric claim as a benign control.
- [x] Ensure checker exceptions fail closed with \`SAFE_FALLBACK\`.
- [x] Run core, pipeline-contract and grounding regression tests in CI.
- [x] Record synthetic-only evaluation limitations.
- [ ] Obtain lead review of cross-team integration; do not merge independently.
