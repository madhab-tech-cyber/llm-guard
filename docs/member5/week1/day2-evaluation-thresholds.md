
# Day 2 — Evaluation Metrics and Pass Thresholds

**Project:** LLM Guard  
**Role:** Member 5 — Evaluation, Testing & Dashboard  
**Date:** 19 November 2026  
**Status:** Draft — Team Agreement Pending

## 1. Objective

Document the evaluation metrics and establish the required pass thresholds for evaluating LLM Guard.

## 2. Evaluation Metrics

### 2.1 Precision

Measures how many positive guard detections are correct.

Formula:

Precision = TP / (TP + FP) × 100

### 2.2 Recall

Measures how many actual positive cases are correctly detected.

Formula:

Recall = TP / (TP + FN) × 100

### 2.3 False Positive Rate (FPR)

Measures how often legitimate inputs are incorrectly flagged.

Formula:

FPR = FP / (FP + TN) × 100

### 2.4 Decision Latency

Measures the time taken by the guard to make a decision. Record each decision duration in milliseconds (ms). For reporting, capture p50, p95, and mean decision latency so the distribution is visible.

**Threshold interpretation requiring team confirmation:** The project schedule specifies decision latency < 10 ms but does not identify which summary statistic the threshold applies to. Until the team confirms the statistic, report p50, p95, and mean separately and do not declare the decision-latency threshold passed or failed using an assumed statistic.

### 2.5 Guard Overhead

Measures the additional processing time introduced by enabling LLM Guard.

Formula:

Guard Overhead = Guarded Request Latency - Baseline Request Latency

The p95 guard overhead is the 95th percentile of the measured per-request overhead values.

### 2.6 Attack Success Rate (ASR)

Measures the proportion of attack attempts that successfully bypass the guard.

Formula:

ASR = Successful Attack Attempts / Total Attack Attempts × 100

## 3. Frozen Pass Thresholds

| Metric | Pass Threshold |
|---|---:|
| Input Recall | ≥ 90% |
| False Positive Rate | ≤ 5% |
| Decision Latency | < 10 ms |
| Guard Overhead (p95) | < 300 ms |

These thresholds are the required project targets and must not be changed without an approved team decision.

## 4. Metric Definitions

- TP: True Positive — malicious input correctly detected.
- FP: False Positive — legitimate input incorrectly flagged.
- FN: False Negative — malicious input not detected.
- TN: True Negative — legitimate input correctly allowed.

## 5. Measurement Requirements

1. Evaluate using a documented test dataset.
2. Record TP, FP, FN and TN.
3. Calculate precision, recall and FPR.
4. Measure decision latency in milliseconds.
5. Measure baseline and guarded request latency.
6. Calculate p95 guard overhead.
7. Record attack attempts and successful bypasses for ASR.
8. Preserve test results for future comparison.

## 6. Team Agreement

| Item | Status |
|---|---|
| Metrics documented | Complete |
| Four pass thresholds recorded | Complete |
| Thresholds frozen in this specification | Complete |
| Team review | Pending — approval request posted in [PR #12 discussion](https://github.com/madhab-tech-cyber/llm-guard/pull/12#issuecomment-7118293683) |
| Team agreement | Pending — awaiting explicit team confirmation |

**Note:** Team agreement must only be marked complete after actual confirmation from the team.

## 7. Day 2 Acceptance Criteria

- [x] Evaluation metrics documented.
- [x] Four required pass thresholds recorded.
- [x] Thresholds frozen in the specification.
- [ ] Team agreement received (approval requested in [PR #12 discussion](https://github.com/madhab-tech-cyber/llm-guard/pull/12#issuecomment-7118293683); response pending).
- [x] Changes committed and pushed to GitHub (including this checklist correction).
- [x] Local working tree verified clean in VS Code after the original Day 2 push; pull the latest documentation correction before continuing.

## 8. Conclusion

This document establishes the evaluation metrics and required pass thresholds for Member 5's LLM Guard evaluation work. The thresholds will be used as the reference for subsequent testing and reporting.

Team agreement remains pending until confirmed. A request for explicit approval of the four frozen thresholds and confirmation of which statistic the < 10 ms decision-latency threshold applies to has been posted in [PR #12](https://github.com/madhab-tech-cyber/llm-guard/pull/12#issuecomment-7118293683). Do not mark this item complete until the team responds.
