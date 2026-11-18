# Day 10 — Member 2 Input Guard: limits checker + module skeleton

**Date:** Saturday 2026-11-21 (Day 10)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** Build the limits checker: max characters, max tokens, max lines. Put all detectors into the module skeleton, with tests. Module skeleton runs; limits tests pass.
**Lab-only rule (from the Member 2 schedule, p.1):** use only synthetic test prompts the team writes itself. Never test on real user data. Every example below is fake — made-up names, `example.test` domains, `FAKE` keys. Test them only against your own Input Guard module / lab setup.
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/detector_limits.py` + `scanners/input-guard/input_guard.py` (plus this note, plus `test_input_guard_day10.py`)
**Status of this file:** starter draft, prepared early (Tue 2026-11-17, evening). **Run + tested Tue 2026-11-17:** `detector_limits.py` + `input_guard.py` + `test_input_guard_day10.py` — 36/36 checks pass. Nothing is pushed.

## Why this day matters, in simple words

Days 6–9 built four detectors that each work alone. Day 10 is the day they become one guard: a single `check_prompt()` that the rest of the pipeline calls, in the exact Day 5 shape (verdict + reasons + scores + masked prompt + timings). It also adds the last judging detector — Detector 5, the limits checker — which stops oversize prompts before they are even judged. After Day 10, Week 2 is complete: all five judging detectors exist and run together.

It builds only on work already done:
- Day 4 design doc v1: 6 detectors, 3 verdicts, v1 thresholds — limits over = block on its own; fail closed on any crash
- Day 5 interface agreement v1: in is prompt + metadata, out is verdict + reasons + scores + masked prompt + timings (still pending Member 1's sign-off)
- Days 6–9: Detectors 1–4, each with its own file and tests — the skeleton imports them unchanged, it does not rewrite them

## Detector 5 — the limits checker (v1 proposals, not measured facts)

No limit was set in the Day 4 doc or the Day 5 agreement, so these numbers are picked here, labelled v1, and left for the team / Day 13 baseline to confirm or change:

| Limit | v1 value | Why this number |
|---|---|---|
| Max characters | 8,000 | A normal chat prompt is a few hundred chars; 8,000 is roughly 2 pages of text |
| Max tokens (estimated) | ~2,000 | Follows from the char limit at ~4 chars per token |
| Max lines | 100 | A prompt pasted as 100+ lines is a document dump, not a question |

Over any one limit → **blocked**, score 1.0, nothing forwarded. Under all three → **clean**, score 0.0. There is no suspicious band in v1: a prompt is either inside the limits or it is stopped.

**Tokens are estimated, not counted.** `est_tokens = ceil(chars / 4)` is the usual rough rule for English text. It is good enough to catch a 50,000-char paste; it is not a real token count and must never be quoted as one. A real tokenizer is a Day 36 / Member 1 job.

## The skeleton — one entry point, in Day 5 shape

```python
from input_guard import check_prompt
check_prompt("Explain how login systems work in general.")
# {'verdict': 'clean', 'reasons': [], 'scores': {...all 6 detectors...},
#  'masked_prompt': '...', 'detector_timings_ms': {...}, 'context': {...}}
```

**Order — a Day 10 decision, written down so Day 15 can challenge it:** limits first (an oversize prompt "is not judged, it is stopped" — Day 4), then encoding, injection, PII, secrets. Sanitizer (Detector 6) is Day 21 work: it reports 0.00 here and changes nothing, but the score key is present so the Day 5 output shape is complete from day one.

**Verdict:** worst score wins, never an average. Blocked if over the limits, any detector at 0.90+, a live secret, or any detector crash — blocked prompts return an empty `masked_prompt`. Suspicious if the highest score is 0.50–0.89 or PII was found — the masked prompt is forwarded. Clean otherwise.

**Masking order:** PII first, then secrets on the PII-masked text. A secret that sat inside a PII span is already gone by then, which is the safe direction.

**Fail closed:** every detector call is wrapped — a crash scores 1.0, the reason says it crashed, and the verdict is blocked. Detectors 2 and 3 already fail closed internally; the wrapper adds the same guard for Detectors 1, 4 and 5.

## Test results (Tue 2026-11-17, run for real)

Runner: `test_input_guard_day10.py` — **36/36 pass**.

- **Limits alone (7 checks):** clean prompt counts correctly (42 chars); exactly 8,000 chars and exactly 100 lines pass; 8,001 chars and 101 lines block at 1.0.
- **Skeleton on the Day 5 worked examples:** clean stays clean with all 6 score keys and all 6 timings; injection and encoded attacks block and forward nothing; PII (email) is suspicious and masked to `[REDACTED:EMAIL]`; a live AWS key blocks and forwards nothing; PII + secret together block.
- **Limits gate through the skeleton:** an 8,001-char prompt blocks before the other detectors run.
- **Empty / whitespace-only prompt:** blocked, not crashed (Day 5 says the sender never sends one — if it arrives anyway, stop it).
- **Speed:** every detector under 50 ms on a normal prompt (slowest ~1.8 ms) — the Day 29 target, checked early.
- **Fail closed, tested for real:** Detector 1 forced to crash mid-run → verdict blocked, reason recorded, nothing forwarded.
- **No regressions:** Day 6/7 suite still 19/21 with the same 2 known false positives, Day 8 still 20/20, Day 9 still 40/40.

## What v1 does NOT do (say so honestly)

- **The two known Day 6 false positives are still there, unchanged.** Quoting the attack phrase (`What does "ignore previous instructions" mean? Just explain the phrase.`) still blocks at 0.95, and `api_key` as a bare variable name in code still scores suspicious at 0.85 (Detector 1, rule R9). Both were already recorded for Day 14 before Day 10 — the skeleton inherits them, it does not fix Detector 1, and the Day 10 test names them as known instead of pretending they pass.
- **Injection and encoding scores overlap by design.** Detector 2 runs Detector 1's rules on decoded text, so one attack raises both scores. The verdict uses the worst score, not a sum, so the overlap cannot double-block a clean prompt — but the two numbers are not independent evidence.
- **`source`, `turn_number` and `history_summary` are accepted but not yet used.** Multi-turn and indirect injection need them (Days 21–23); this skeleton only records them in the result for now.
- **Token count is an estimate** (see above). A prompt that is long in another language, or packed with short words, will estimate wrong.
- **The v1 limits are guesses.** If real prompts in the Day 12 test set are longer than 8,000 chars for honest reasons, the limit moves — the Day 13 baseline decides, not this file.

## Handoff to Days 11–13

- **Day 11:** 20 unit tests per detector — the Day 10 test file is the start, not the full set.
- **Day 12:** the 100-prompt labelled test set (50 benign, 50 attack) must include the two known Day 6 false positives and prompts near the limits, or the baseline will look better than it is.
- **Day 13:** baseline metrics. The v1 limits and thresholds stand until those numbers say otherwise.
- **Day 15 checkpoint:** show this skeleton running end to end, with the 4 detectors standalone and the baseline metrics.
