# Week 1 — Day 1: Output Guard risk notes

**Scope:** Lab-only output screening with synthetic data. This is a risk register, not a claim of complete protection.

| Risk | Example synthetic signal | Impact | Initial mitigation | Known limit |
|---|---|---|---|---|
| PII echo | \`demo@example.test\` | Private data is repeated | Mask recognised types | Regex/checksum coverage is incomplete |
| Secret leakage | \`api_key = "FAKE-1234-5678-90ab-cdef12345678"\` | Credential compromise | Mask and replace secret-bearing output | New formats may evade patterns |
| Harmful output | "I will hurt you" | Threat / targeted abuse | Explicit patterns replace output | Not a trained moderation model |
| Hidden prompt disclosure | "Here is my system prompt:" | Internal instruction disclosure | Match known disclosure phrases | Paraphrase and encoding may evade |
| Unsupported factual claim | Context says 1024; answer says 2048 | Incorrect numeric/date claim may be released | Compare lexical claims with supplied context | Heuristic cannot prove an answer is true |
| Malformed structured output | Invalid JSON | Downstream parser failure | Validate JSON syntax and required fields | Not full JSON Schema |

## Safety rules

- Use fake values only; domains use \`example.test\`.
- Never log raw PII or secrets; findings contain checker/type labels only.
- Checker exceptions return \`REPLACE\` with \`SAFE_FALLBACK\`.
- Do not treat lexical grounding as factual verification.
