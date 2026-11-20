# Day 4 — Evaluation Harness Design

- **Owner:** Member 5 — Evaluation, Testing & Dashboard
- **Week:** 1
- **Task type:** Planning / design
- **Status:** Design specification
- **Data policy:** Synthetic evaluation data only

## 1. Objective

Design a repeatable harness that loads the agreed evaluation dataset, submits each test case to a guard through a replaceable adapter, records the guard's actual verdict and timing, compares that verdict with the expected verdict, and produces reproducible metrics and saved results.

Day 4 defines the architecture and implementation plan. It does **not** claim that a guard has been evaluated or that any metric has been achieved.

## 2. Scope and ownership

The harness and evaluation datasets belong to Member 5. Input Guard, Output Guard, and Policy Engine implementations remain owned by their respective members. Member 5 measures and reports their behavior; the owning member fixes detector or policy defects.

The initial harness should support an input-guard adapter and allow later adapters for the Output Guard and Policy Engine without changing the dataset contract or result-record format.

## 3. Dataset contract

The Day 3 dataset format remains the source of truth:

| Field | Type | Meaning |
|---|---|---|
| `prompt` | string | Synthetic input to evaluate |
| `expected_verdict` | string | Expected normalized outcome, initially `allow` or `block` |
| `category` | string | Evaluation category, such as benign, injection, jailbreak, PII, or toxicity |

The loader will:
1. Read the agreed dataset file (initially JSONL or the exact format selected in the Day 3 dataset documentation).
2. Validate that every record contains all three required fields and that values are non-empty.
3. Validate the expected-verdict vocabulary for the selected guard adapter.
4. Reject malformed records with a useful line/record number; do not silently skip or relabel them.
5. Assign or derive a stable case ID for traceability without changing the three required dataset fields.
6. Record the dataset path, content hash, and case count in run metadata.

Only synthetic prompts are permitted. Dataset changes should be version-controlled so results can be tied to the exact input set.

## 4. Harness workflow

1. **Configure run:** select dataset, guard adapter, run ID, and execution settings.
2. **Load and validate:** parse every case and fail clearly on invalid input.
3. **Execute:** send each prompt to the selected guard using the agreed module interface. Keep guard-specific invocation details inside an adapter.
4. **Capture actual verdict:** preserve the raw response and normalize the decision into the agreed verdict vocabulary. Do not infer a verdict from the expected value.
5. **Measure timing:** measure elapsed wall-clock time around the guard decision call with a monotonic high-resolution clock. Store the per-case duration in milliseconds.
6. **Compare:** compare normalized actual and expected verdicts and classify the outcome.
7. **Aggregate:** calculate overall and per-category metrics from completed, valid comparisons.
8. **Persist:** save case-level records, run metadata, and a summary before reporting results.

A test case that errors, times out, or returns an unrecognized verdict is recorded as an execution error with its raw details. It is not silently counted as a correct allow/block decision. Report the error count and denominator explicitly; do not hide failures by dropping them from the run.

## 5. Guard adapter contract

The harness calls a small adapter interface rather than importing detector internals directly.

Conceptual contract:

- Input: one dataset case (at minimum its `prompt`).
- Operation: invoke the guard's documented public entry point.
- Output: raw guard response, normalized actual verdict, and timing information.
- Error behavior: surface timeout, exception, and invalid-response details to the harness.

The exact function name, request/response model, and verdict mapping must be agreed with the module owner during the Day 5 interface discussion. Do not invent or assume another member's API. Preserve the raw response for auditability, subject to the lab's synthetic-data-only rule.

For an Output Guard or a multi-action policy module, define a guard-specific mapping before scoring. Do not force actions such as redact, sanitize, or review into allow/block without an explicit, documented mapping.

## 6. Verdict comparison and confusion matrix

For the initial binary input-guard evaluation, treat **block / malicious** as the positive class:

| Expected | Actual | Classification |
|---|---|---|
| block | block | True positive (TP) |
| allow | allow | True negative (TN) |
| allow | block | False positive (FP) |
| block | allow | False negative (FN) |

Each case-level record retains both `expected_verdict` and `actual_verdict`. The comparison outcome is an additional field; it never replaces either verdict.

## 7. Metrics and calculation rules

Calculate metrics only from completed cases with valid expected and actual verdicts. Publish the evaluated-case count, error count, and category breakdown beside every metric.

- **Precision:** TP / (TP + FP). If the denominator is zero, report `null` / not defined, not zero.
- **Recall:** TP / (TP + FN). If the denominator is zero, report `null` / not defined.
- **False-positive rate (FPR):** FP / (FP + TN). If the denominator is zero, report `null` / not defined.
- **Decision latency:** per-case elapsed decision time; report distribution statistics (at least mean and p50/p95 when enough observations exist) and the unit (ms).
- **Guard overhead (p95):** measure separately from decision latency when an end-to-end baseline without the guard is available. Document the measurement method and baseline; do not treat the two latency measures as interchangeable.

For multi-category datasets, calculate the same applicable classification metrics overall and per category. State the denominator for every rate. Do not round values in stored raw results; apply display rounding only in reports.

### Frozen project thresholds

The Day 2 thresholds are locked and must not be modified by this harness or by later reports:

| Metric | Threshold |
|---|---:|
| Input recall | ≥ 90% |
| False positives | ≤ 5% |
| Decision latency | < 10 ms |
| Guard overhead (p95) | < 300 ms |

The schedule labels the false-positive target as a maximum of 5%; reports should show the measured FPR / false-positive result and the precise denominator so the comparison is transparent. Precision has no separate pass threshold specified in the schedule: report it, but do not invent one.

## 8. Result persistence and traceability

Each run must be saved under a dated, version-controlled `results/` location in a later implementation step. Proposed layout:

```text
results/
  YYYY-MM-DD/
    <run-id>/
      run-metadata.json
      case-results.jsonl
      summary.json
```

Minimum case-result fields:

- `case_id`
- `prompt` (synthetic only)
- `expected_verdict`
- `actual_verdict` (null only when no valid verdict was returned)
- `raw_response` or a safe serialized representation
- `category`
- `comparison` (`TP`, `TN`, `FP`, `FN`, or `ERROR`)
- `latency_ms`
- `error_type` and `error_message` when applicable

Minimum run metadata: run ID, timestamp (UTC), dataset path and content hash, dataset case count, guard/module identifier and version or commit, adapter version, execution configuration, and harness version.

The summary stores metric values, metric denominators, evaluated count, error count, category-level counts, and threshold comparisons. A summary must link to its case-level records and metadata. Never publish a metric without a saved run that supports it.

## 9. Reliability and reproducibility

- Use deterministic case ordering by default.
- Record concurrency, timeout, retry, and warm-up settings in run metadata.
- Do not retry silently; any retry policy must be explicit and recorded.
- Keep raw expected and actual verdicts immutable after capture.
- Distinguish execution errors from detector false negatives or false positives.
- Record the guard commit/version so a later run can be compared fairly.
- Use synthetic data only; do not place real prompts, secrets, or personal data in datasets or results.

## 10. Implementation plan

| Step | Planned work | Completion evidence |
|---|---|---|
| 1 | Confirm the Day 3 dataset schema and file format | Loader contract matches the saved Day 3 documentation |
| 2 | Define the adapter interface with the relevant module owner(s) | Day 5 interface notes and runnable invocation |
| 3 | Implement dataset loading and validation | Valid records load; malformed records fail clearly |
| 4 | Implement adapter execution and timing | Each case records raw response, normalized verdict, latency, or error |
| 5 | Implement verdict comparison | TP/TN/FP/FN mapping covered by unit tests |
| 6 | Implement metric aggregation | Formula and zero-denominator tests pass |
| 7 | Implement result persistence | Metadata, case results, and summary are saved per run |
| 8 | Add CLI/report output | Run prints a concise summary and points to saved artifacts |
| 9 | Validate with synthetic fixtures and a stub adapter | Repeatable tests; no fabricated guard performance claims |
| 10 | Integrate live guard adapters when module interfaces are available | Results identify the tested module version and dated run |

Implementation is planned for the project's Python 3.12 stack. The harness should be testable with a stub adapter before other members' modules are ready, then use the real documented module interface when available.

## 11. Day 4 completion checklist

- [x] Evaluation harness workflow defined.
- [x] Dataset loading and validation planned.
- [x] Guard invocation through an adapter defined.
- [x] Actual verdict capture and preservation defined.
- [x] Expected-versus-actual comparison defined.
- [x] Metrics and edge cases defined.
- [x] Architecture diagram saved separately.
- [x] Implementation plan documented.
- [ ] Files committed and pushed to the Member 5 branch.

**Day 4 status:** Design documentation only. No live guard evaluation has been run as part of this task, and no evaluation score is claimed.
