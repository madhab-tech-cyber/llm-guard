# Day 15 — Member 2 Input Guard: team checkpoint (design + skeletons)

**Date:** Thu 26 Nov 2026 (Day 15) — prepared Mon 23 Nov 2026
**Role:** Member 2 — Input Guard, LLM Guard
**Branch:** `member2-input-guard` (tip `2d5dc12`, Day 14)
**Done-when from the schedule:** Show the design doc, the 4 detectors working standalone, and the baseline metrics. Checkpoint demo done; feedback logged.
**Lab-only rule:** all prompts are synthetic (fake names, `example.test`, FAKE keys).

## 1. What to show (5-minute demo)

1. **Design doc** — `day4-input-guard-design.md`: 6 detectors, 3 verdicts (clean / suspicious / blocked), v1 thresholds, one `check_prompt()` entry point, fail closed. Interface shape = `day5-interface-agreement.md`.
2. **4 detectors standalone** — run `python3 day15_checkpoint_demo.py`. Each detector scores a clean prompt 0.0 and an attack prompt high:

| Detector | Clean | Attack |
|---|---|---|
| 1. Injection | 0.0 | 0.95 |
| 2. Jailbreak + encoding (base64) | 0.0 | 0.95 |
| 3. PII (email) | 0.0 | 0.70 |
| 4. Secrets (AWS-style key) | 0.0 | 0.95 |

   End to end, `check_prompt()` gives: clean question → **clean**; injection → **blocked**; email → **suspicious** with the email masked as `[REDACTED:EMAIL]`; secret → **blocked**. The limits checker (8,000 chars / ~2,000 tokens / 100 lines) also runs.
3. **Baseline metrics** — run `python3 test_day13_baseline.py` on the 100-prompt labelled set (50 benign + 50 attack):

| Metric | Day 13 baseline | Day 14 (now) | Target |
|---|---|---|---|
| Recall | 0.52 | **0.54** | ≥ 0.90 |
| False-positive rate | 0.08 | **0.00** | ≤ 0.05 ✅ |
| Precision | 0.867 | 1.000 | — |
| F1 | 0.650 | 0.701 | — |
| Accuracy | 0.72 | 0.77 | — |
| Blocked-only recall | 0.30 | 0.30 | — |

## 2. Test status (re-run 23 Nov 2026)

Day 6/7 detectors: no failures · Day 8 PII 20/20 · Day 9 secrets 40/40 · Day 10 `check_prompt()` 36/36 · Day 11 unit tests 100/100 (~0.04 ms per call, target < 50 ms) · Day 12 smoke 100/100 · Day 14 false-positive fixes 24/24.

## 3. Known gaps (honest list)

- **Recall 0.54, target 0.90 not met.** 23 attacks still slip. Clusters:
  - paraphrased direct injections ("Forget everything above…") — rules are narrow keywords
  - roleplay jailbreaks without the trigger words
  - ROT13 / reversed / URL-encoded text — not decoded yet
  - indirect injection (pasted "system:" text) — source/history not used until Days 21–23
  - PII shapes: SSN, IBAN, street address, one Aadhaar example
  - secret shapes: GitHub/OpenAI-style tokens, plain passwords
- Day 14 trade-offs logged for Day 28: bare "Pretend you are DAN", first-person "From now on, I will answer as…", "return the api_key", "My Assistant:" planted turn.
- Morse / homoglyph decoding not built yet.
- Plan: Days 16–20 add an ML classifier beside the rules; Days 21–23 indirect + multi-turn.

## 4. Raise with the team today (schedule says: raise at Day 15, not Day 24)

- **Member 1:** Day 5 interface agreement still needs your sign-off. If your integration skeleton is late, my Days 24–25 slip too.
- **Member 4:** confirm you consume `verdict` + `scores` + `masked_prompt` as in Day 5, and that the final block/allow call is yours.
- **Member 5:** the 100-prompt set (`day12_test_set.json`) is ready for your eval harness.
- No PR from `member2-input-guard` to `main` yet — ask the team when they want it.

## 5. Feedback log (fill in at the meeting)

| From | Feedback | Action | By day |
|---|---|---|---|
| | | | |
| | | | |
