# Day 8 — Member 2 Input Guard: PII scanner (Detector 3)

**Date:** Thursday 2026-11-19 (Day 8)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** Build the PII scanner using regex plus named-entity rules for the Day 3 list. PII scanner flags the test examples.
**Lab-only rule (from the Member 2 schedule, p.1):** use only synthetic test prompts the team writes itself. Never test on real user data. Every example below is fake — made-up names, `example.test` domains, `FAKE` keys. Test them only against your own Input Guard module / lab setup.
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/detector_pii.py` (plus this note, plus `test_detector_pii_day8.py`)
**Status of this file:** starter draft, prepared early (Sun 2026-11-15, evening). **Run + tested Sun 2026-11-15:** `detector_pii.py` + `test_detector_pii_day8.py` — 20/20 checks pass, timing 0.05 ms per call (target < 50 ms). Nothing is pushed.

## Why this day matters, in simple words

Days 6–7 caught bad instructions. Day 8 catches bad *data*: a user pastes their own private details into the prompt, and the model then stores it, repeats it, or leaks it. The guard must spot private data *before* the prompt reaches the LLM — mask it, then let the prompt through. PII is usually an accident, so unlike secrets (Day 9) it is masked, not blocked.

It builds only on work already done:
- Day 3: the 14 PII types, each with a fake example, a pattern, and its false-positive trap
- Day 4 design doc v1: Detector 3 is the PII scanner; verdicts clean / suspicious / blocked; v1 thresholds — PII found lands at suspicious (0.50–0.89); targets ≥ 90% recall, ≤ 5% false positives, < 50 ms, fail closed
- Day 5 interface agreement v1: in is prompt + metadata, out is verdict + reasons + scores + masked prompt (still pending Member 1 sign-off)
- Day 3 handoff: one masking format for both scanners — `[REDACTED:TYPE]` — so Member 3 (Output Guard) and Member 4 (Policy Engine) read the same tags

## What v1 catches (all 14 Day 3 types)

| # | Type | How v1 finds it | Mask |
|---|---|---|---|
| 1 | Name | "my name is / I am / contact" + two capitalised words — regex alone cannot do names (Day 3) | `[REDACTED:NAME]` |
| 2 | Email | standard email regex | `[REDACTED:EMAIL]` |
| 3 | Phone | `+` country code, or Indian mobile `[6-9]` + 9 digits with phone context | `[REDACTED:PHONE]` |
| 4 | Aadhaar | 12 digits + Verhoeff checksum (the check is what makes it safe to flag) | `[REDACTED:AADHAAR]` |
| 5 | PAN | `[A-Z]{5}[0-9]{4}[A-Z]` + identity context (PAN / tax / card) | `[REDACTED:PAN]` |
| 6 | Passport | `[A-Z][0-9]{7}` + passport / travel-document context | `[REDACTED:PASSPORT]` |
| 7 | Address | street word (Road / Street / Nagar…) + 6-digit PIN in the same prompt | `[REDACTED:ADDRESS]` |
| 8 | DOB | date shape + DOB / born / birth context | `[REDACTED:DOB]` |
| 9 | Card | 16 digits + Luhn checksum | `[REDACTED:CARD]` |
| 10 | Bank / IFSC | IFSC `[A-Z]{4}0[A-Z0-9]{6}`; account 9–18 digits + bank context | `[REDACTED:IFSC]` / `[REDACTED:BANK_ACCOUNT]` |
| 11 | Driving licence | `[A-Z]{2}[0-9]{2}[0-9]{4}[0-9]{7}` | `[REDACTED:DRIVING_LICENCE]` |
| 12 | IP | valid octets (0–255) + IP / server context | `[REDACTED:IP]` |
| 13 | GPS | two decimals with 4+ places, comma pair | `[REDACTED:GPS]` |
| 14 | Handle | `@handle` + identity context | `[REDACTED:HANDLE]` |

Verdict: any PII found → **suspicious, 0.70**, masked prompt returned. No PII → **clean**. Never blocked for PII alone — that is Day 9's job for secrets. Reasons name the TYPE only, never the value — the raw value must never reach a log.

## Test results (Sun 2026-11-15, run for real)

Runner: `test_detector_pii_day8.py` — **20/20 pass.**

**All 14 Day 3 examples flagged**, each masked to its `[REDACTED:TYPE]` tag — name, email, +91 phone, Aadhaar, PAN, passport, address, DOB, test-range card (Luhn-valid), IFSC + bank account together, driving licence, IP, GPS, handle.

**Benign traps all stay clean (6/6):** a plain prompt; a 10-digit order number with no phone context; version `1.2.3.4` (not an IP); a date with no DOB context; a PAN-shaped product code with no identity context.

**Timing:** 0.05 ms per call (target < 50 ms).

## Two things that look wrong — both are by design, not bugs

1. **The Day 3 Aadhaar example `2345 6789 0123` does NOT flag.** It fails the Verhoeff checksum — Day 3 itself says the example is fake and a real Aadhaar follows the checksum. The scanner is doing exactly what Day 3 asked: the checksum is what separates a real Aadhaar shape from any random 12-digit number. The test uses a Verhoeff-valid fake instead, `2345 6789 0121`, which does flag. Do not "fix" this by dropping the checksum.
2. **The address mask is coarse.** There is no single regex for an address (Day 3), so v1 masks up to 60 characters before the PIN. In the test that swallows the whole sentence — which is correct for an address, but on a long prompt it could mask words that are not part of the address. Record it for Day 14; do not pretend the boundary is exact.

Two fixes made during the test run, both written down here so Thursday is not a mystery: the name rule first missed "My name is…" because its cue was lowercase-only, then over-matched "contact me there" as a name once made case-insensitive — the final rule spells the cue out (`[Mm]y name is…`) and keeps the name itself capitalised. The phone rule first flagged an order number because "number" counted as phone context — "number" was removed from the context list.

## What v1 does NOT do (say so honestly)

- **Real NER for names:** v1 only catches a name after "my name is / I am / contact". A name dropped in with no cue ("Rahul Sharma said…") passes v1. That needs a name list or NER model (Day 3's own note) — not a regex.
- **Address boundaries:** see point 2 above — the 60-char mask is a rough cut.
- **Secrets:** an API key or token in the same prompt is NOT this detector's job. Day 9 builds the secrets scanner; do not bolt secret patterns onto Detector 3.
- **Indirect / multi-turn injection:** same limits as Days 6–7 — still needs the Day 5 `source` and history fields.

## Test it on Thursday (30 minutes, before calling it done)

1. **The 14 Day 3 examples:** every one flagged and masked, as in the runner above. The Aadhaar one to use is `2345 6789 0121` (Verhoeff-valid fake), not the Day 3 example as written — that one stays clean by design.
2. **Benign prompts that must stay clean:** the 6 traps in the runner (order number, version number, bare date, PAN-shaped product code, plain prompt). Any of these flagged is a false positive to note for Day 14, not a rule to quietly delete.
3. **Timing:** time the detector on a normal prompt. Target under 50 ms per detector (checked properly on Day 29) — record Thursday's number; Sunday's was 0.05 ms.
4. **Fail closed:** if the detector crashes or times out on a prompt, that prompt is blocked, never waved through (Day 4 design, Day 46 check). The code already returns blocked on exception.

## Done when (schedule)

PII scanner flags the test examples — the 14 Day 3 examples flagged and masked, benign prompts clean, scores + reasons coming out in the Day 5 shape, and the misses / false positives written down for Day 11's unit tests (20 cases per detector) and Day 14's false-positive fixes.

## Handoff

- **Day 9 (Fri 2026-11-20):** secrets scanner — the Day 3 list (10 secret types), block on live secrets. Same `[REDACTED:TYPE]` mask format, same Day 5 shape.
- **Day 11:** 20 unit tests for this detector (good and bad prompts), from Thursday's run plus the misses found (name without a cue, address boundary).
- **Day 13:** baseline metrics on the 100-prompt set — this v1 score (0.70 for any PII) is what gets measured.
- **Day 14:** false-positive fixes — the address mask boundary, plus the Day 6–7 known ones (talking *about* the phrase, `api_key` as a variable name, Morse, homoglyphs).

## Sources used (not copied word-for-word)

- Member 2 60-day schedule, Week 2 (Days 6–10): Day 8 PII scanner
- Day 3 file: 14 PII types, patterns, false-positive traps, mask/block handling, Day 8 handoff
- Day 4 design doc v1: 6 detectors, 3 verdicts, v1 thresholds, targets (≥ 90% recall, ≤ 5% false positives, < 50 ms, fail closed)
- Day 5 interface agreement v1: in prompt + metadata, out verdict + reasons + scores + masked prompt (pending Member 1 sign-off)

## Count check

- PII types in v1: 14 (all of Day 3 Part A)
- Tests: 20 checks, 20 pass (14 flagged + 6 benign clean)
- Known limits named: 4 (names without a cue, address boundary, secrets are Day 9, indirect/multi-turn — same as Days 6–7)
