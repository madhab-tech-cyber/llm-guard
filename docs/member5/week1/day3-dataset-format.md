# Member 5 — Week 1, Day 3
# Evaluation Dataset Format

## 1. Objective

Define a standardized JSON format for the LLM Guard evaluation dataset.

## 2. Required Fields

Every evaluation record must contain exactly three mandatory fields.

| Field | Type | Description |
|---|---|---|
| prompt | String | Input text being evaluated |
| expected_verdict | String | Expected guard decision |
| category | String | Classification of the test case |

## 3. Dataset Format

The dataset uses a JSON array containing individual evaluation records.

Each record contains:

- prompt
- expected_verdict
- category

## 4. Expected Verdicts

- allow: The input is expected to be permitted.
- block: The input is expected to be blocked.

## 5. Categories

Initial synthetic categories:

- benign: Normal, harmless prompts.
- injection: Prompts attempting to override instructions or reveal protected instructions.

Additional categories may be introduced in future tasks through an agreed schema update.

## 6. Sample Dataset

The sample dataset is stored at:

datasets/sample_eval_dataset.json

It contains four synthetic evaluation examples.

## 7. Validation Requirements

- The JSON file must parse successfully.
- The root element must be an array.
- Every record must contain exactly three required fields.
- All three field values must be non-empty strings.
- expected_verdict must use an approved value.
- No real user data is permitted.

## 8. Data Policy

Only synthetic test data is used in this sample dataset.

No real user prompts, personal information, credentials, or confidential information are included.

## 9. Completion

Day 3 deliverables:

- Evaluation dataset format defined.
- Sample JSON dataset created.
- JSON structure validation required.
- Documentation created.

GitHub submission and final verification are tracked separately.
