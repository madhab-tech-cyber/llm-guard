"""Day 18 tests - LLM Guard Member 2 (lab-only, synthetic prompts).

Heuristic vs ML pick one ("Referee Mode").
Run: python3 test_day18_referee.py      (~30-60 s: refits the train-only model once)

Checks
1. combine(): each mode's logic, including "ML never blocks in referee"
   and "ML never downgrades".
2. ML missing / crashed -> every mode falls back to heuristics, never blocks.
3. Default mode is the Day 18 choice; all 100 Day 12 verdicts identical
   to day16_verdicts_pre.json.
4. scores / detector_timings_ms key sets unchanged; new "referee" key present
   on every path (normal, empty, non-string, over-limit).
5. Referee mode on Day 12 changes ONLY clean -> suspicious, never blocks.
6. Cutoff picked on validation only: re-running the pick on the Day 17
   validation split gives the stored cutoff; Day 12 / test are not used.
7. Determinism: two runs give identical scores and verdicts.
8. day18_metrics.json numbers reproduce from the saved model.
"""
import json
import os

import detector_ml
import input_guard
from input_guard import combine, check_prompt

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0


def check(name, ok, extra=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name} {extra}")


def load(n):
    return json.load(open(os.path.join(HERE, n), encoding="utf-8"))


met = load("day18_metrics.json")
d12 = load("day12_test_set.json")["items"]
pre = load("day16_verdicts_pre.json")
KEYS = ["injection", "jailbreak_encoding", "limits", "pii", "sanitizer", "secrets"]

# 1. combine() logic
c = 0.43
check("heuristics mode ignores ML", combine("clean", 0.99, "heuristics", c) == ("clean", "none"))
check("referee upgrades clean at cutoff", combine("clean", 0.43, "referee", c)[0] == "suspicious")
check("referee leaves clean below cutoff", combine("clean", 0.429, "referee", c)[0] == "clean")
check("referee never blocks (ML 0.99)", combine("clean", 0.99, "referee", c)[0] == "suspicious")
check("referee never downgrades blocked", combine("blocked", 0.01, "referee", c)[0] == "blocked")
check("referee never downgrades suspicious", combine("suspicious", 0.01, "referee", c)[0] == "suspicious")
check("referee keeps suspicious as suspicious (no block)",
      combine("suspicious", 0.99, "referee", c)[0] == "suspicious")
check("or mode upgrades clean at 0.43", combine("clean", 0.43, "or")[0] == "suspicious")
check("or mode blocks at 0.90", combine("clean", 0.90, "or")[0] == "blocked")
check("or mode never downgrades", combine("blocked", 0.0, "or")[0] == "blocked")
try:
    combine("clean", 0.5, "vote")
    check("unknown mode rejected", False)
except ValueError:
    check("unknown mode rejected", True)

# 2. ML missing -> heuristics only, never a block
for m in input_guard.MODES:
    check(f"{m}: ML None keeps clean", combine("clean", None, m, c)[0] == "clean")
real = input_guard.detect_injection_ml


def boom(_):
    raise RuntimeError("simulated ML crash")


input_guard.detect_injection_ml = boom
try:
    crash_diff = []
    for it in d12:
        for m in input_guard.MODES:
            r = check_prompt(it["prompt"], mode=m)
            if r["verdict"] != pre[it["id"]] or r["referee"]["ml_score"] is not None:
                crash_diff.append((it["id"], m))
    check("ML crash: all 3 modes = heuristic verdicts on 100 prompts", not crash_diff, str(crash_diff[:5]))
    r = check_prompt("What is the capital of France?", mode="referee")
    check("ML crash: action ml_unavailable, verdict clean",
          r["verdict"] == "clean" and r["referee"]["action"] == "ml_unavailable")
finally:
    input_guard.detect_injection_ml = real

# 3. Default + verdicts unchanged
check("default mode is the Day 18 choice (heuristics)", input_guard.GUARD_MODE == "heuristics")
diff = [i["id"] for i in d12 if check_prompt(i["prompt"])["verdict"] != pre[i["id"]]]
check("all 100 Day 12 verdicts identical to pre-Day-16 (default mode)", not diff, f"changed: {diff}")

# 4. Key sets + referee key on every path
paths = {"normal": "Explain how a will differs from a trust.", "empty": "   ",
         "non-string": 42, "over-limit": "x" * 8001}
# Pre-Day-18 key sets per path. Over-limit has always returned only
# limits + sanitizer (the gate stops before the other detectors run) -
# an existing quirk, kept unchanged and noted in day18-heuristic-vs-ml.md.
WANT = {"normal": KEYS, "empty": KEYS, "non-string": KEYS, "over-limit": ["limits", "sanitizer"]}
for name, p in paths.items():
    r = check_prompt(p)
    check(f"{name}: scores keys unchanged", sorted(r["scores"]) == WANT[name])
    check(f"{name}: timing keys unchanged", sorted(r["detector_timings_ms"]) == WANT[name])
    check(f"{name}: referee key present", set(r["referee"]) == {
        "mode", "heuristic_verdict", "ml_score", "cutoff", "action", "referee_opinion"})
for name in ("empty", "non-string", "over-limit"):
    for m in input_guard.MODES:
        r = check_prompt(paths[name], mode=m)
        check(f"{name} still blocked in {m} mode", r["verdict"] == "blocked" and r["masked_prompt"] == "")

# 5. Referee mode on Day 12: only clean -> suspicious
bad = []
upgraded = []
for it in d12:
    r = check_prompt(it["prompt"], mode="referee")
    h = pre[it["id"]]
    if r["verdict"] != h:
        if not (h == "clean" and r["verdict"] == "suspicious"):
            bad.append(it["id"])
        else:
            upgraded.append(it["id"])
            if r["masked_prompt"] != it["prompt"]:
                bad.append(it["id"] + ":masked")
check("referee mode changes only clean -> suspicious, forwards prompt", not bad, str(bad))
check("referee upgrades = 6 benign + 13 ML catches (19)", len(upgraded) == 19, str(len(upgraded)))
check("default mode reports referee_opinion for B24 (second opinion visible)",
      check_prompt(next(i["prompt"] for i in d12 if i["id"] == "B24"))["referee"]["referee_opinion"]
      == "suspicious")

# 6. Cutoff from validation only
import day18_referee_eval as ev  # noqa: E402

train, val, test, _ = ev.build_split()
check("split sizes match Day 17 (500/126/116)", (len(train), len(val), len(test)) == (500, 126, 116))
tm = detector_ml.TfidfLogReg(l2=met["l2"], min_df=2).fit([t for t, _ in train], [y for _, y in train])
vx, vy = [t for t, _ in val], [y for _, y in val]
cut, vm = ev.pick_referee_cutoff([ev.heur_verdict(t) for t in vx],
                                 [round(tm.predict_proba(t), 3) for t in vx], vy)
check("validation re-pick gives the stored cutoff", cut == met["referee_cutoff"] == input_guard.REFEREE_CUTOFF,
      f"{cut} vs {met['referee_cutoff']}")
check("validation FP rate of chosen cutoff <= 5%", vm["fp_rate"] <= 0.05, str(vm))
d12_norm = {" ".join(i["prompt"].lower().split()) for i in d12}
check("no Day 12 prompt in the validation split",
      not any(" ".join(t.lower().split()) in d12_norm for t in vx))

# 7. Determinism
a = [check_prompt(i["prompt"], mode="referee") for i in d12[:30]]
b = [check_prompt(i["prompt"], mode="referee") for i in d12[:30]]
check("deterministic verdicts + ML scores",
      [(x["verdict"], x["referee"]["ml_score"]) for x in a] ==
      [(x["verdict"], x["referee"]["ml_score"]) for x in b])

# 8. Metrics reproduce
labels = [1 if i["label"] == "attack" else 0 for i in d12]
for m in input_guard.MODES:
    flags = [check_prompt(i["prompt"], mode=m)["verdict"] != "clean" for i in d12]
    tp = sum(1 for y, f in zip(labels, flags) if y and f)
    fp = sum(1 for y, f in zip(labels, flags) if not y and f)
    want = met["results"]["day12"][m]
    check(f"Day 12 {m} numbers reproduce via check_prompt", (tp, fp) == (want["tp"], want["fp"]),
          f"{tp}/{fp} vs {want['tp']}/{want['fp']}")

print(f"\n{passed} passed, {failed} failed")
print("ALL PASS" if not failed else "SOME FAILED")
raise SystemExit(1 if failed else 0)
