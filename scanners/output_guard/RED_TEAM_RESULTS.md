# Output Guard Red-Team Results

## Scope
A safe, deterministic corpus of 30 synthetic strings probes PII patterns, toxicity phrases, prompt-leakage phrases and JSON checks, with benign controls. It does not invoke tools or access external systems.

Run:
    python -m unittest scanners.output_guard.test_red_team -v
    python -m scanners.output_guard.red_team

## Test groups
| Group | Cases | Probes |
|---|---:|---|
| PII | 6 | Email/phone/PAN and spaced, bracketed, encoded variants |
| Toxicity | 6 | Direct threats, case changes, homoglyph and punctuation variants |
| Prompt leakage | 6 | Explicit disclosure phrases, paraphrases and encoded text |
| Format | 6 | Malformed JSON, required fields, root type, nested object and wrapped JSON |
| Benign | 6 | Ordinary security terminology and clean text |

## Reading the report
- expected_pattern_misses lists cases where the expected checker did not report.
- benign_false_positives counts benign controls with any finding.
- Results are exploratory coverage indicators, not accuracy estimates.

## Initial security observations
The current implementation is pattern-based. Unicode homoglyphs, punctuation insertion, encoded strings and paraphrased disclosure may evade exact regular expressions. JSON validation checks syntax and configured top-level required fields; it does not enforce a complete JSON Schema. These are reported as gaps, not hidden by weakening test assertions.

## Limitations
This hand-authored corpus is small, deterministic and not independently labelled. It is not exhaustive or representative of real attacks, and does not prove production security.
