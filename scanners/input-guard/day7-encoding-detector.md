# Day 7 — Member 2 Input Guard: encoding detector (Detector 2)

**Date:** Wednesday 2026-11-18 (Day 7)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** Detect base64, hex and Unicode tricks hidden inside a prompt. Decode, then check the decoded text. Encoding detector working with tests.
**Lab-only rule:** use only synthetic test prompts the team writes itself. Never test on real user data. Every example below is fake. Test them only against your own Input Guard module / lab setup.
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/detector_encoding.py` (reuses `detector_injection.py` — do not rebuild the rules)
**Status:** built + tested Sun 2026-11-15 (ahead of Wednesday). Nothing is pushed.

## Why this day matters, in simple words

Day 6 catches plain-text injection. Day 7 catches the same attack wearing a disguise: base64, hex, ROT13, reversed text, URL-encoding, Unicode escapes, leetspeak. The rule from Day 2 is **decode first, then check** — the decoded text goes through the exact same Detector 1 rules, so nothing is rebuilt and no rule can drift out of sync.

## What v1 decodes (and what it does not)

| Method | How v1 finds it | Decoded, then checked? |
|---|---|---|
| Base64 | long token of letters/digits/`+`/`/` with `=` padding | Yes |
| Hex | long even-length hex token | Yes |
| ROT13 / Caesar | cue words ("rot13", "caesar", "cipher") + letter-shifted token | Yes |
| Reversed text | cue words ("backwards", "reversed") + reversed token | Yes |
| URL-encoded | `%XX` sequences | Yes |
| Unicode escapes | `\uXXXX` sequences | Yes |
| Leetspeak | `1337` substitutions normalised (`0`→o, `1`→i, `3`→e, `4`→a, `5`→s, `7`→t) | Yes, but suspicious only (0.80) — never blocked on leetspeak alone |
| Morse | — | **No, v1 limit** — flagged for Day 14 |
| Unicode-lookalike homoglyphs | — | **No, v1 limit** — flagged for Day 14 |

Decode only when there is a cue word or a long encoded-looking token. Decoding everything (ROT13 on all normal text, for example) would flag innocent words. That guard is why the benign base64 token and the hex-looking order id in the tests stay clean.

## Test results (Sun 2026-11-15, run for real)

Runner: `test_detectors_day6_7.py` — 21 checks total.

**Day 7 — 10/10 pass:**
- Day 2 examples #8–12 all caught: base64 → blocked (0.95), hex → blocked (0.95), ROT13 → blocked (0.95), reversed → blocked (0.95), leetspeak → suspicious (0.80).
- Extra synthetic checks: URL-encoded → blocked, Unicode-escape → blocked.
- Benign stays clean: normal prompt, a docs base64 token (`aGVsbG8gd29ybGQ=` decodes to harmless words), a hex-looking order id.

**Day 6 (same run) — 10/12 pass, 2 known false positives** (already predicted in the Day 6 file, recorded for Day 14, rules not deleted):
- Talking *about* the phrase — "What does 'ignore previous instructions' mean?" → blocked (0.95). R1 cannot tell using the phrase from mentioning it.
- `api_key` as a variable name in a code sample → suspicious (0.85). R9 fires on any mention.

**Timing:** Detector 1: 0.02 ms/call, Detector 2: 0.03 ms/call (target < 50 ms per detector, Day 4).

## What v1 does NOT do (say so honestly)

- **Morse and homoglyph lookalikes:** not decoded in v1. A prompt in Morse or with Cyrillic lookalike letters passes v1. Day 14's false-positive/missed-case pass is where these get handled — do not bolt them on now.
- **Token smuggling / payload splitting (Day 2, #15–20):** splitting the attack across pieces so no single piece matches is a different problem — rejoining pieces before checking. That is not this detector's job.
- **Indirect injection (Day 1, #9–14):** still needs the `source` field from the Day 5 interface — an instruction hiding in retrieved content is data, never instructions. Same limit as Day 6.
- **Multi-turn injection (Day 1, #15–20):** still needs `turn_number` + `history_summary`. Same limit as Day 6.

## Handoff

- **Day 8 (Thu 2026-11-19):** PII scanner — regex + named-entity rules for the Day 3 list (14 PII types). Reuse the Day 5 shape (verdict + reasons + scores + masked prompt).
- **Day 9 (Fri 2026-11-20):** secrets scanner — the Day 3 list (10 secret types), block on live secrets.
- **Day 11:** 20 unit tests per detector — the Day 6/7 test lists above are the starting set, plus the misses found (the 2 false positives, Morse, homoglyphs).
- **Day 13:** baseline metrics on the 100-prompt set — these v1 scores are what gets measured.
- **Day 14:** false-positive fixes — the 2 known ones from Day 6, plus Morse/homoglyph coverage.

## Sources used (not copied word-for-word)

- Member 2 60-day schedule, Week 2 (Days 6–10): Day 7 encoding detector
- Day 2 file: encoding tricks #8–14 (base64, hex, ROT13, reversed, leetspeak, Unicode lookalikes, Morse)
- Day 4 design doc v1: 6 detectors, 3 verdicts, v1 thresholds, targets (≥ 90% recall, ≤ 5% false positives, < 50 ms, fail closed)
- Day 5 interface agreement v1: in prompt + metadata, out verdict + reasons + scores + masked prompt (pending Member 1 sign-off)
- Day 6 file + `detector_injection.py`: the rules Detector 2 reuses

## Count check

- Encodings decoded in v1: 7 (base64, hex, ROT13, reversed, URL-encoded, Unicode escapes, leetspeak)
- Limits named: 4 (Morse, homoglyphs, token smuggling, indirect/multi-turn — same as Day 6)
- Tests: 21 checks, 19 pass, 2 known false positives (Day 6, predicted)
