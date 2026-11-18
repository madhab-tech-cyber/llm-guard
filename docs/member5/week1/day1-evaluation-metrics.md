# Member 5 — Week 1, Day 1: Evaluation Fundamentals

## 1. Day 1 objective

Understand the five evaluation metrics used to assess LLM guardrails: precision, recall, false-positive rate, latency, and attack success rate (ASR). Learn the confusion matrix terms and practise calculating the metrics using a synthetic dataset.

## 2. Five evaluation metrics

### 2.1 Precision

Precision answers: **Of all prompts flagged as attacks, how many were actually attacks?**

A high precision score means the guard does not frequently mistake normal prompts for attacks among the prompts it flags.

**Formula:**

`Precision = TP / (TP + FP) × 100`

### 2.2 Recall

Recall answers: **Of all actual attack prompts, how many did the guard detect?**

A high recall score means the guard catches a large proportion of the attacks in the evaluation set.

**Formula:**

`Recall = TP / (TP + FN) × 100`

### 2.3 False-positive rate (FPR)

The false-positive rate answers: **Of all normal prompts, how many were incorrectly flagged as attacks?**

A high false-positive rate means legitimate users are more likely to have harmless prompts blocked or flagged.

**Formula:**

`FPR = FP / (FP + TN) × 100`

### 2.4 Latency

Latency is the time the guard takes to process a request. It is measured in milliseconds (`ms`).

Three useful measurements are:

- **p50:** Median latency; half of the measured requests have latency at or below this value.
- **p95:** 95th-percentile latency; 95% of measured requests have latency at or below this value.
- **Average:** Mean latency across the measured requests.

Latency matters because guardrails should provide protection without making normal interactions unnecessarily slow. Looking at p50, p95, and average latency gives a more useful picture than relying on only one timing value.

### 2.5 Attack success rate (ASR)

Attack success rate answers: **What proportion of attack attempts successfully bypassed the guard?**

A lower ASR indicates that fewer tested attacks succeeded in bypassing the guard.

**Formula:**

`ASR = Successful attacks / Total attack attempts × 100`

## 3. Confusion matrix terms

| Term | Meaning |
|---|---|
| **TP — True Positive** | A malicious prompt is correctly detected as malicious. |
| **FP — False Positive** | A normal prompt is incorrectly flagged as malicious. |
| **FN — False Negative** | A malicious prompt is incorrectly allowed. |
| **TN — True Negative** | A normal prompt is correctly allowed. |

The confusion matrix helps organize the guard's predictions against the actual labels of the prompts.

## 4. Worked example — synthetic practice data

Assume an evaluation uses **200 synthetic prompts**:

- 100 attack prompts.
- 100 normal prompts.
- 90 attacks detected.
- 10 attacks missed.
- 5 normal prompts incorrectly flagged.
- 95 normal prompts correctly allowed.

These values produce the following confusion matrix:

| | Predicted attack | Predicted normal | Actual total |
|---|---:|---:|---:|
| Actual attack | TP = 90 | FN = 10 | 100 |
| Actual normal | FP = 5 | TN = 95 | 100 |
| Predicted total | 95 | 105 | 200 |

### 4.1 Precision

`Precision = TP / (TP + FP) × 100`

`= 90 / (90 + 5) × 100`

`= 90 / 95 × 100 = 94.74%`

### 4.2 Recall

`Recall = TP / (TP + FN) × 100`

`= 90 / (90 + 10) × 100`

`= 90 / 100 × 100 = 90%`

### 4.3 False-positive rate

`FPR = FP / (FP + TN) × 100`

`= 5 / (5 + 95) × 100`

`= 5 / 100 × 100 = 5%`

### 4.4 Attack success rate

For this simplified example, assume each missed attack represents a successful bypass.

`ASR = Successful attacks / Total attack attempts × 100`

`= 10 / 100 × 100 = 10%`

### 4.5 Results summary

| Metric | Calculation | Result |
|---|---|---:|
| Precision | 90 / 95 × 100 | **94.74%** |
| Recall | 90 / 100 × 100 | **90%** |
| False-positive rate | 5 / 100 × 100 | **5%** |
| Attack success rate | 10 / 100 × 100 | **10%** |

**Important:** These are synthetic practice numbers only. They are not actual LLM Guard measurements or benchmark results. Latency was not supplied in this example, so no latency result is claimed.

## 5. Why each metric matters in LLM Guard

| Metric | Why it matters |
|---|---|
| Precision | Helps assess whether prompts flagged by the guard are genuinely malicious, reducing unnecessary blocking of legitimate prompts. |
| Recall | Helps assess whether the guard detects the attacks present in the test set. |
| False-positive rate | Helps measure how often legitimate prompts are incorrectly flagged, which affects usability. |
| Latency | Helps assess the processing-time cost introduced by the guard, including slower requests near the p95 level. |
| Attack success rate | Helps measure how often tested attacks get past the guard; lower is generally better. |

These metrics should be considered together. For example, a guard that catches many attacks but also blocks many normal prompts may have strong recall but an unacceptable false-positive rate.

## 6. Review checklist

- [x] All five metrics defined.
- [x] Precision, recall, false-positive rate, and ASR formulas included.
- [x] Latency explained in milliseconds, including p50, p95, and average.
- [x] TP, FP, FN, and TN explained.
- [x] Worked example and calculations completed.
- [x] Practice dataset explicitly labelled synthetic.
- [x] No actual evaluation or benchmark results invented.
- [ ] File committed and pushed to the Member 5 branch.
- [ ] File opened on GitHub and verified.

## 7. Conclusion

Day 1 establishes the basic measurements needed to evaluate an LLM guardrail. Precision and recall describe detection quality from different perspectives; false-positive rate measures incorrect blocking of normal prompts; latency measures processing time; and attack success rate measures successful attack bypasses. The confusion matrix provides the counts needed to calculate the classification metrics.

The example in these notes is synthetic and is intended only to practise the calculations. Actual LLM Guard performance must be measured using a documented evaluation dataset and test run.

**Day 1 status:** Study notes prepared. Repository commit, push, and GitHub verification are still pending.
