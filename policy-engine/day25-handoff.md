# Days 24–25 standalone handoff

Status: local lab verification on 28 November 2026; not a Member 1 proxy integration or team contract sign-off.

The branch now includes current Member 2 input-guard and Member 3 output-guard code from `main`. A ten-synthetic-prompt smoke test feeds Member 2's `check_prompt(..., mode="heuristics")` verdict and scores directly to `policy_engine.decide`. A separate clean-output test checks Member 3's `inspect_output` score shape. Both pass. Output score names `toxicity`, `prompt_leakage`, `format`, `grounding` and `input` are recognized; their meaning and policy mappings remain proposed. The existing synthetic output-secret rule expects `secrets`, which Member 3 does not currently emit, so it fails closed if used with that adapter.

There is no runnable Member 1 proxy in the inspected `member1-lead-architecture` branch. No live request forwarding, verified mask provenance or FLAG delivery was tested. A standalone `masked_available=False` prevents an unverified REDACT. Member 1 must accept the call points, detector mappings and audit acknowledgement before integration.

Run: `PYTHONPATH=. python3 -m unittest tests.test_policy_input_guard_handoff tests.test_policy_output_guard_handoff -v` after installing `policy-engine/requirements.txt`.
