# Day 9 — Member 2 Input Guard: secrets scanner (Detector 4)

**Date:** Friday 2026-11-20 (Day 9)
**Role:** Member 2 — Input Guard, LLM Guard
**Done-when from the schedule:** Build the secrets scanner using the Day 3 Part B patterns. Secrets scanner flags the test examples.
**Lab-only rule (from the Member 2 schedule, p.1):** use only synthetic test prompts the team writes itself. Never test on real user data. Every example below is fake — AWS's own published examples, `FAKE` keys, `example.test` domains. Test them only against your own Input Guard module / lab setup.
**Repo:** github.com/madhab-tech-cyber/llm-guard — branch `member2-input-guard`
**Suggested path when pushed:** `scanners/input-guard/detector_secrets.py` (plus this note, plus `test_detector_secrets_day9.py`)
**Status of this file:** starter draft, prepared early (Sun 2026-11-15, evening). **Run + tested Sun 2026-11-15:** `detector_secrets.py` + `test_detector_secrets_day9.py` — 40/40 checks pass, 0.10 ms per call (target < 50 ms). Nothing is pushed.

## Why this day matters, in simple words

Days 6–7 caught bad instructions, Day 8 caught bad personal data. Day 9 catches the dangerous one: a live key or password pasted into a prompt. A leaked key works immediately — anyone who sees it can use it — so unlike PII (mask and let through), a real secret **blocks** the request. The prompt never reaches the LLM, and the raw value never reaches a log.

It builds only on work already done:
- Day 3 Part B: the 10 secret types, each with a fake example, a pattern, and its false-positive trap
- Day 4 design doc v1: Detector 4 is the secrets scanner; verdicts clean / suspicious / blocked; v1 thresholds — any live secret blocks (≥ 0.90); targets ≥ 90% recall, ≤ 5% false positives, < 50 ms, fail closed
- Day 5 interface agreement v1: in is prompt + metadata, out is verdict + reasons + scores + masked prompt (still pending Member 1's sign-off)
- Day 3 handoff: one masking format for both scanners — `[REDACTED:TYPE]` — so Member 3 (Output Guard) and Member 4 (Policy Engine) read the same tags

## What v1 catches (all 10 Day 3 types)

| # | Type | How v1 finds it | Result |
|---|---|---|---|
| 1 | AWS access key | `AKIA` + 16 chars — prefix proves it | blocked 0.95 |
| 2 | AWS secret key | 40-char base64 **only with AWS context words nearby** (Day 3 trap: the shape alone is generic) | blocked 0.90 |
| 3 | GitHub token | `ghp_` + 36 chars, or `github_pat_` + 22 | blocked 0.95 |
| 4 | Stripe key | `sk_live_` / `rk_live_` + 16 chars | blocked 0.95 |
| 5 | Generic API key | key name (`api_key`, `access_token`, …) + `=`/`:` + a real-looking 16+ char value with letters **and** digits | blocked 0.90 |
| 6 | Private key block | `-----BEGIN … PRIVATE KEY-----` — header alone blocks, full block masked to the END line | blocked 0.95 |
| 7 | JWT | `eyJ…​.eyJ…​.…` — three base64url parts | blocked 0.95 |
| 8 | Password | `password:` / `=` / `my password is` + a value actually given | blocked 0.90 |
| 9 | DB connection string | `(postgres\|mysql\|mongodb\|redis)://user:pass@host` — only the `user:pass@` part is masked, host stays | blocked 0.95 |
| 10 | Webhook URL | `hooks.slack.com/services/…` or `discord.com/api/webhooks/…` | blocked 0.90 |

Verdict: any live secret → **blocked**, masked prompt returned. No secret → **clean**. Reasons name the TYPE only, never the value — the raw value must never reach a log.

## Test results (Sun 2026-11-15, run for real)

Runner: `test_detector_secrets_day9.py` — **40/40 pass** (20 prompts with secrets, 20 code samples without), plus the `sk_test_` exception check.

**All 20 secret prompts blocked**, each masked to its `[REDACTED:TYPE]` tag — two AWS keys, two AWS secrets, two GitHub tokens, two live Stripe keys, two generic keys, two private-key blocks, two JWTs, two passwords, two DB strings, two webhooks. The password and the DB credential are gone from the masked prompt; the DB host stays, by design.

**All 20 benign code samples stay clean**, including the traps Day 3 warned about:
- `api_key` as a bare variable name (`def call(api_key)`, `print(api_key)`, `api_key = None`) — this is the Day 7 false positive, fixed here by requiring a real 16+ char value with letters and digits. Recorded for Day 14 anyway.
- `password = getpass.getpass()` — a function call, not a password; the value rule rejects it.
- Docs wording: "Set your password…", "How do I reset my password?", "AWS keys start with AKIA", "JWTs start with eyJ", a bare `BEGIN PUBLIC KEY`, a Slack URL with no token, a Postgres URL with no login.

**Timing:** 0.10 ms per call (target < 50 ms).

## The one exception — by design, not a bug

**`sk_test_` keys are suspicious (0.50), never blocked.** Day 3 says so plainly: developers paste test keys constantly, and blocking them breaks testing. The test runner checks this separately and it passes: `sk_test_…​` → suspicious, masked to `[REDACTED:STRIPE_TEST_KEY]`, allowed through at low severity. `sk_live_` still blocks at 0.95.

## What v1 does NOT do (say so honestly)

- **A 40-char AWS secret with no context words nearby passes.** That is the Day 3 rule, not a miss — the shape alone matches any long token. If Friday's testing shows real prompts carry AWS secrets without the words, the rule needs a second signal, not a looser pattern.
- **A password inside a longer sentence with unusual characters may pass.** The value rule allows letters, digits and common symbols; a password with a space or a quote in it is cut short. Real passwords rarely have spaces; note it for Day 14.
- **No secret rotation or revocation advice.** The guard blocks and masks; telling the user their key is now exposed and must be rotated is a Day 10 (skeleton) / policy job, not this detector's.
- **Morse + homoglyph lookalikes are still open limits** (same as Days 6–7) — an encoded secret that does not decode to a known prefix will not flag until the encoding detector runs first. Day 10 pulls Detectors 1–4 together, so that ordering is the fix.
