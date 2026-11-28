# Day 11 — Member 2 Input Guard: unit tests for each detector

**Date:** Wednesday 2026-11-18 (built early; schedule date is Sunday 2026-11-22)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** "Write unit tests for each detector —
20 cases each, good and bad prompts. 80+ unit tests written and passing."
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/test_detectors_day11.py`
(plus this note)
**Status:** built and tested Wed 2026-11-18. **Nothing is pushed.**

## Test results (Wed 2026-11-18, run for real)

Runner: `test_detectors_day11.py` — **100/100 pass**.

| Detector | Cases | Result |
|---|---|---|
| 1 Injection (Day 6 rules R1–R9) | 20 (10 attack + 10 benign) | 20/20 |
| 2 Encoding (Day 7 decode-first) | 20 (10 attack + 10 benign) | 20/20 |
| 3 PII scanner (Day 8, all 14 types) | 20 (14 types + 6 benign traps) | 20/20 |
| 4 Secrets scanner (Day 9, all 10 types) | 20 (10 blocked + sk_test_ exception + 9 benign) | 20/20 |
| 5 Limits checker (Day 10 boundaries) | 20 (boundaries + counts) | 20/20 |

- **Speed:** ~0.03 ms average per detector call (target < 50 ms).
- **No regressions:** Day 10 suite still 36/36, Day 9 still 40/40,
  Day 8 still 20/20 — all re-run the same day.
- **Expectations were probed first:** every case's expected verdict was
  checked against the detector's actual v1 behaviour before locking it
  in, so a pass means the test matches the detector, not a guess.

## What the tests actually cover (new, not repeats)

- **Injection:** every rule R1–R9 fires at least once, and six benign
  prompts that look dangerous stay clean ("What is a system prompt…?",
  "Ignore the noise…", "Act as a teacher…", "Send me the report…").
- **Encoding:** all seven decode paths block — base64 (with and without
  a cue word), hex, ROT13, reversed, URL-encoded, unicode-escape — plus
  leetspeak at suspicious (0.80) by design, and benign encoded text
  (a base64/hex "Hello world" and a ROT13 explanation) stays clean.
- **PII:** the Day 8 set re-run from this one file, so Day 11 covers
  every detector in a single run.
- **Secrets:** one blocked case per Day 3 type, the sk_test_ exception
  (suspicious, never blocked), and 9 benign traps including the Day 7
  fix (bare `api_key` variable stays clean).
- **Limits:** exact boundaries — 7999 vs 8000 vs 8001 chars, 99 vs 100
  vs 101 lines, token estimate 2000 vs 2001 — with the counts checked,
  not just the verdict. Empty prompt is clean at detector level; the
  Day 10 skeleton blocks it, and that split is written in the file.

## Honest limits — false positives recorded for Day 14

These four cases pass against *current* behaviour and are labelled in
the file, so Day 14 fixes the detector instead of the test:

1. **Known FP #1 (Day 6):** quoting the attack phrase —
   `What does "ignore previous instructions" mean?` — blocks at 0.95.
2. **Known FP #2 (Day 6):** bare `api_key` variable in code scores
   suspicious at 0.85 (Detector 1, rule R9).
3. **NEW FP candidate:** `From now on, I will study every day.` scores
   suspicious at 0.70 — rule R7 fires on "from now on" alone.
4. **NEW FP candidate:** `My assistant: Sarah, can you help me study?`
   scores suspicious at 0.85 — rule R5 fires on any "assistant:".

Day 14 should tighten R5 and R7 (require an instruction after the
marker) and re-check #1 and #2, then re-run this file — the two new
candidates will flip from suspicious to clean when fixed.

## Push note (Day 9 lesson, applied here)

The fake Stripe values in this file are exactly 16 chars after
`sk_live_` — the length that cleared GitHub's secret scanner when Day 9
was pushed. Do not lengthen them, or the push will be rejected again.

## Handoff to Days 12–13

- **Day 12:** the 100-prompt labelled test set (50 benign, 50 attack).
  It must include the four false positives above and prompts near the
  limits, or the baseline will look better than it is.
- **Day 13:** baseline metrics (precision / recall). The v1 thresholds
  and limits stand until those numbers say otherwise.
- **Day 15 checkpoint:** this file is the unit-test evidence — 100
  cases, all passing, with the four FPs named, not hidden.
