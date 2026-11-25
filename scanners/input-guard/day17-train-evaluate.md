# Day 17 — Train and evaluate the ML classifier (Member 2, Input Guard)

Schedule says: *train and evaluate the classifier on your test set plus public datasets. Note every dataset source.* Done when: *classifier scores recorded, sources noted.*

## Data used (every source)

| Data | What | Source | Licence | Use |
|---|---|---|---|---|
| `day17_public_deepset.json` | 662 prompts (546 train + 116 test), English and German, label 1 = injection | Hugging Face `deepset/prompt-injections` — https://huggingface.co/datasets/deepset/prompt-injections, revision `4f61ecb038e9c3fb77e21034b22511b523772cdd`, fetched 25 Nov 2026 | apache-2.0 (the card also lists cc-by-4.0 in one block; both allow reuse with credit) | train / validation / held-out test |
| `day16_train_set.json` | 80 hand-written synthetic prompts (40 benign + 40 attack) | our own (Day 16) | repo licence | train / validation |
| `day12_test_set.json` | our 100-prompt labelled set (50 benign + 50 attack) | our own (Day 12) | repo licence | **evaluation only, never trained on** |

The public data is copied unchanged so training works offline and gives the same result every time. It is public research data with no secrets.

## How the split works (no peeking)

- **Held-out TEST** = deepset's own test split, 116 prompts (60 attacks). Not used for any choice.
- **TRAIN / VALIDATION** = deepset train (546) + our seed (80) = 626, shuffled with seed 17, split 80/20 → **500 train, 126 validation**.
- **Leakage checks** (all 0): no prompt in train/val/test equals a Day 12 prompt; none is a near-copy (word overlap ≥ 0.8); no training prompt equals a test prompt; no duplicates inside the pool.
- Settings were picked on **validation only**: L2 strength (0.0001 / 0.001 / 0.01) and the score cutoff. The cutoff rule: the highest recall whose validation false-positive rate stays at or under 5%.
- Then the model was refit on train + validation and measured **once** on the test set and once on the Day 12 set.

## Chosen settings

L2 = 0.0001, cutoff = **0.43**, features seen in at least 2 prompts (22,875 features). Validation: recall 0.896, precision 0.935, FP rate 0.038.

## Results

**Held-out public test (116 prompts):**

| Detector | Recall | Precision | FP rate | F1 |
|---|---|---|---|---|
| Heuristics (today's verdict) | 0.017 (1/60) | 1.000 | 0.000 | 0.033 |
| **ML classifier (Day 17)** | **0.783 (47/60)** | **1.000** | **0.000** | **0.879** |

**Our Day 12 set (100 prompts, all 50 attacks incl. PII/secrets):**

| Detector | Recall | Precision | FP rate | F1 |
|---|---|---|---|---|
| Heuristics (baseline) | 0.540 | 1.000 | 0.00 | 0.701 |
| ML classifier alone | 0.480 | 0.800 | 0.12 | 0.600 |
| Heuristics OR ML | 0.800 | 0.870 | 0.12 | 0.833 |

**Day 12, injection-type attacks only** (direct, roleplay, indirect, encoded = 30 attacks + 50 benign — PII and secrets are not the classifier's job): heuristics recall 0.467, **ML recall 0.800**, ML FP rate 0.12.

What this means in plain words:

- On public data the heuristics catch almost nothing (many prompts are German or phrased in ways our keywords never saw). The ML catches 78% with zero false alarms.
- On our own set, the ML catches **13 attacks the heuristics miss** (A04–A10, A12–A14, A16, A26, A30 — mostly paraphrased injections).
- But it raises **6 false alarms** on our benign prompts: B16 and B21 (coding requests), B24 (a question *about* "ignore previous instructions"), B27, B28, B30 (the same tricky-benign cases Day 14 fixed in the heuristics). 12% is above the ≤5% target.
- It misses all encoded attacks (base64, hex, ROT13, reversed, unicode) — it reads words, not decoded text — and A18 (roleplay). PII and secrets are out of scope by design.

## Where it sits: still shadow only

- `detector_ml.py` now **loads the saved model** (`day17_model.json`) instead of training at start-up. First call ~33 ms (was ~3 s). If the file is missing, it falls back to the Day 16 seed model.
- The shadow's "suspicious" band now starts at the validation cutoff 0.43; "blocked" stays 0.90. This only labels the shadow score.
- **Verdicts are still decided by the heuristics alone. All 100 Day 12 verdicts are identical to before Day 16.** The `scores` and `detector_timings_ms` keys are unchanged.
- Warm latency with the shadow on: mean ~0.53 ms, p95 ~0.85 ms, max ~1.25 ms (far under 10 ms).

## Files

- `day17_train_eval.py` — rebuilds everything (≈1.5 min, plain Python): split, leakage checks, validation grid, final fit, numbers.
- `day17_model.json` — the trained model (≈850 KB).
- `day17_metrics.json` — every number above.
- `day17_public_deepset.json` — the public dataset with its source block.
- `test_day17_train_eval.py` — Day 17 tests (21 checks).
- `detector_ml.py` — `min_df` option, saved-model loading, fallback.
- `test_day16_ml_classifier.py` — only the smoke-preview label changed (it now says which model it used).

## Tests (run 25 Nov 2026)

`test_day17_train_eval.py`: **21/21 pass.** Older suites all green: Day 6/7 no failures · Day 8 PII 20/20 · Day 9 secrets 40/40 · Day 10 36/36 · Day 11 100/100 · Day 12 smoke OK · Day 13 baseline unchanged (recall 0.540, precision 1.000, F1 0.701, 0 FPs) · Day 14 24/24 · Day 15 demo runs · Day 16 all pass.

## Honest limits

- 626 training prompts is still small, and about a third are German. Our users write in English, so the public test score may flatter it.
- The deepset test split comes from the same source as its train split, so 0.783 is an "in-family" score. The Day 12 set is the tougher, out-of-family check — there ML alone is weaker than the heuristics.
- 6 false alarms on our benign set: the ML can't yet tell talking *about* an attack from doing one.
- No decoding: encoded attacks need the encoding detector to decode first (Day 7 gap).
- Hand-rolled TF-IDF + logistic regression, no scikit-learn; settings grid is small (3 values).

## Next

**Day 18:** put heuristic vs ML side by side and pick the default, keeping the other as fallback. Today's numbers point to "heuristics decide, ML as a second opinion" (OR gives recall 0.80 but FP 0.12), unless the ML false alarms on tricky-benign prompts can be fixed first. Day 19: confidence scores. Day 20: detector README.
