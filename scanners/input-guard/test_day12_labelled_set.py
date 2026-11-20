"""Day 12 smoke runner — LLM Guard Member 2 (lab-only, synthetic prompts).

Loads day12_test_set.json (100 labelled prompts) and runs each through
check_prompt() from input_guard.py. This is a SMOKE check only: it
verifies every prompt loads and returns a verdict without crashing.
It does NOT score agreement between verdicts and labels — measuring
precision/recall against the labels is Day 13's job (schedule date
Tue 2026-11-24). Do not quote verdict counts from this run as a
baseline; that would be Day 13's number, done properly.

Run: python3 test_day12_labelled_set.py  (from this folder)
"""
import json
import time

from input_guard import check_prompt

with open("day12_test_set.json") as f:
    data = json.load(f)

items = data["items"]
assert len(items) == 100, f"expected 100 prompts, got {len(items)}"
assert sum(1 for i in items if i["label"] == "benign") == 50
assert sum(1 for i in items if i["label"] == "attack") == 50

started = time.perf_counter()
crashed = []
verdicts = {}
for it in items:
    try:
        result = check_prompt(it["prompt"])
        verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1
    except Exception as exc:  # noqa: BLE001 - smoke check must report, not die
        crashed.append((it["id"], repr(exc)))

elapsed = time.perf_counter() - started
print(f"loaded: {len(items)} prompts (50 benign + 50 attack)")
print(f"verdicts returned: {verdicts}")
print(f"crashed: {len(crashed)} {crashed if crashed else ''}")
print(f"total time: {elapsed:.2f}s ({elapsed / len(items) * 1000:.1f} ms per prompt)")
print("SMOKE OK - all 100 prompts ran" if not crashed else "SMOKE FAILED")
