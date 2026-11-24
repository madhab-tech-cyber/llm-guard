# Day 16 — ML classifier option (Member 2, Input Guard)

Schedule says: *add a lightweight classifier for injection (a small transformer, or a scikit-learn TF-IDF baseline to start).* Done when: *classifier runs beside the heuristics.*

## What I built

- **`detector_ml.py`**: a small ML injection classifier. It uses TF-IDF features and logistic regression.
- **`day16_train_set.json`**: an 80-prompt seed training set, 40 benign and 40 attack. All prompts are hand-written and synthetic.
- **`input_guard.py`**: `check_prompt()` now also runs the classifier, but **as a shadow only**.
- **`test_day16_ml_classifier.py`**: the Day 16 tests.
- **`day16_verdicts_pre.json`**: the verdicts on all 100 Day 12 prompts from *before* today's change. The test uses it to prove nothing changed.

## Why plain Python, not scikit-learn

scikit-learn is not installed here. Writing it by hand also means **zero new dependencies**, so Member 5's adapter still just imports `input_guard`. The idea is the same as sklearn's `TfidfVectorizer` + `LogisticRegression`. If the team wants sklearn later, it's an easy swap.

## How it works

- **Features:** lower-cased words, word pairs, and character 3–5 grams. Char grams catch some spelling tricks.
- **Weights:** TF-IDF with smoothed idf, then each vector is scaled to length 1.
- **Model:** logistic regression with plain gradient descent (L2 = 0.001, learning rate 2.0, 300 passes). There's no randomness, so the same data always gives the same model.
- **Score bands:** the same as the other detectors. 0.50 and up is suspicious, 0.90 and up is blocked. Today these bands only label the shadow score.
- **Training cost:** the model trains once, on the first call. That takes about 3 seconds here. After that it's cached.

## Where it sits: shadow only

`check_prompt()` now returns three extra top-level keys:

- `shadow_scores: {"injection_ml": <score or None>}`
- `shadow_timings_ms: {"injection_ml": <ms>}`
- `shadow_reasons: [...]`

It is **not** in `scores` or `detector_timings_ms`. **The verdict is still decided by the heuristics alone.** If the model crashes, the shadow score is `None` and a reason is recorded. The verdict does not change, and it does not fail closed, because it's only a shadow. Empty or over-limit prompts skip the model, so their shadow score is `None`. Day 18 picks which detector becomes the default.

## Test results (run 24 Nov 2026)

**`test_day16_ml_classifier.py`: all 19 checks pass.**
- 0 training prompts appear in the Day 12 test set.
- Two fresh fits give identical scores.
- New benign prompts all score below new attack prompts (benign max 0.313, attack min 0.786).
- **All 100 Day 12 verdicts are the same as before Day 16.**
- The new shadow keys are present, and the `scores` and `detector_timings_ms` keys are unchanged.
- A simulated ML crash keeps all 20 verdicts the same and records the reason.

**Older suites re-run, all green:**

| Suite | Result |
|---|---|
| Day 6/7 | no failures |
| Day 8 PII | 20/20 |
| Day 9 secrets | 40/40 |
| Day 10 | 36/36 |
| Day 11 | 100/100 |
| Day 12 | smoke OK, 0 crashes |
| Day 14 | 24/24 |
| Day 15 | demo runs |

**Day 13 baseline is unchanged:** recall 0.540, precision 1.000, F1 0.701, 0/50 false positives.

**Latency with the shadow on (warm model, 100 prompts):** mean 0.48 ms, p95 0.74 ms, max 0.97 ms. That's still far under the 10 ms target.

## Smoke preview: NOT a result

On the Day 12 set at 0.5, the seed model flags **26/50 attacks** and **2/50 benign** (B24 at 0.62, B39 at 0.51). **14 of those attacks are ones the heuristics miss.** That's a good sign for Day 18. But read it as a smoke test, not a result:

- 80 training prompts is tiny.
- I tried 3 settings and picked one by looking at the Day 12 numbers. That is peeking at the test set. Day 17 needs a proper validation split.
- Several scores sit right on 0.5 (B29 0.499, B38 0.497, A34 0.500), so small changes flip them.

## Honest limits

- It only covers injection and jailbreak wording. PII, secrets, encoding and limits stay with their own detectors.
- It has not been tested on public data yet.
- **Day 17:** train and evaluate on public datasets, with sources noted.
- **Day 18:** compare heuristic vs ML and pick the default.

## Non-string input fix (24 Nov 2026, with Day 16, NOT pushed yet)

`check_prompt()` used to crash with `AttributeError` on a non-string
input (e.g. an int) because the empty-prompt check called `.strip()`
before any detector ran. Member 5 was told about this gap on 24 Nov.
Fix: an `isinstance(prompt_text, str)` guard at the top of
`check_prompt()` now returns blocked, limits 1.0, masked `""`, shadow
`None` — fail closed, no crash. Tested for int, float, list, dict,
bytes and `None` (all blocked). Day 16 tests now 25 checks, all pass;
all older suites re-run green (Day 6/7, 8: 20/20, 9: 40/40, 10: 36/36,
11: 100/100, 12 smoke OK, 13 baseline unchanged, 14: 24/24, Day 15
demo runs). Day 12 verdicts still identical to pre-Day-16. Nothing
pushed to GitHub — push is madhab's call.

## How to run

```
python3 detector_ml.py               # two-line demo
python3 test_day16_ml_classifier.py  # Day 16 tests + preview + latency
```

You don't need to install anything. It's plain Python 3.
