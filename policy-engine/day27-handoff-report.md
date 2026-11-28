# Days 26–27 hundred-case handoff report

Run on 28 November 2026 with the versioned Member 2 `scanners/input-guard/day12_test_set.json` corpus (50 benign, 50 attack labels), Member 2 heuristic mode and Member 4 `lab-policy.yaml`. This is a **standalone lab handoff**, not a Member 1 proxy test, held-out policy evaluation or production accuracy claim.

| Input Guard verdict | Count | Policy action | Count |
| --- | ---: | --- | ---: |
| clean | 73 | ALLOW | 73 |
| blocked | 15 | BLOCK | 15 |
| suspicious | 12 | FLAG | 12 |

Of 50 benign-labelled cases, 50 were ALLOW. Of 50 attack-labelled cases, 15 were BLOCK, 12 FLAG and **23 ALLOW**. These 23 are a material detection gap in this lab combination. The policy engine did not have a signal to distinguish them; raising policy severity cannot fix scores that remain below thresholds. FLAG is not counted as a block, and its delivery semantics remain unapproved. These labels are Member 2's engineering corpus, not an independent held-out set.

Automated checks assert 100 audited decisions, no raw prompts or scanner reasons in the audit rows, and every upstream blocked verdict stays BLOCK. Ten separate synthetic prompt smoke cases and one clean Member 3 output case also pass. No live proxy path, safe mask provenance, route-failure or latency evidence exists yet.

Reproduce after installing `policy-engine/requirements.txt`:

```sh
PYTHONPATH=. python3 -m unittest tests.test_policy_hundred_case_handoff -v
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_policy*.py' -q
```

Follow-up for Members 1–3: agree on required score fields, output-secret mapping, mask provenance and FLAG behavior. Member 2 should triage the 23 labelled attacks its current heuristic mode returns clean; Member 4 should rerun this handoff after detector changes.
