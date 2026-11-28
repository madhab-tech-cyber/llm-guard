"""LLM Guard - Member 2 - Input Guard
Day 18: heuristic vs ML - pick one ("Referee Mode" comparison).

Run: python3 day18_referee_eval.py     (no pip install, ~1-2 min)

What it does
1. Rebuilds the exact Day 17 seed-17 split (same leakage rules, same
   data) and checks the sizes match day17_metrics.json (500 / 126 / 116).
2. Fits a TRAIN-only model with the Day 17 settings (l2 0.0001, min_df 2).
   The saved day17_model.json was refit on train+val, so it has already
   seen the validation prompts - scoring validation with it would cheat.
3. Picks the REFEREE cutoff on VALIDATION only: the cutoff giving the
   highest recall of the whole referee system (heuristics + ML upgrade)
   with validation FP rate <= 5%. Ties -> the higher (safer) cutoff.
4. Measures ONCE, with the deployed day17_model.json, three modes on the
   Day 12 set (100) and the deepset held-out test (116):
     heuristics only / OR mode / Referee mode.
5. Writes the disagreement table and everything else to day18_metrics.json.
"""
import json
import os
import random
import time

import detector_ml
import input_guard
from day17_train_eval import SEED, jaccard, metrics, norm, wset

HERE = os.path.dirname(os.path.abspath(__file__))


def build_split():
    """Same logic and order as day17_train_eval.main()."""
    pub = json.load(open(os.path.join(HERE, "day17_public_deepset.json"), encoding="utf-8"))
    seed_t, seed_y = detector_ml.load_training_set()
    d12 = json.load(open(os.path.join(HERE, "day12_test_set.json"), encoding="utf-8"))["items"]
    d12_norm = {norm(i["prompt"]) for i in d12}
    d12_sets = [wset(i["prompt"]) for i in d12]

    def near_d12(t):
        return norm(t) in d12_norm or any(jaccard(wset(t), x) >= 0.8 for x in d12_sets)

    test = [(r["text"], int(r["label"])) for r in pub["test"] if not near_d12(r["text"])]
    test_norm = {norm(t) for t, _ in test}
    pool, seen = [], set()
    for t, y in [(r["text"], int(r["label"])) for r in pub["train"]] + list(zip(seed_t, seed_y)):
        n = norm(t)
        if near_d12(t) or n in test_norm or n in seen:
            continue
        seen.add(n)
        pool.append((t, y))
    random.Random(SEED).shuffle(pool)
    cut = int(0.8 * len(pool))
    return pool[:cut], pool[cut:], test, d12


def heur_verdict(text):
    return input_guard.check_prompt(text, mode="heuristics")["verdict"]


def flagged(v):
    return v in ("blocked", "suspicious")


def pick_referee_cutoff(heur, ml, labels, max_fpr=0.05):
    best = None
    for c in [x / 100 for x in range(5, 100)]:
        preds = [flagged(input_guard.combine(h, s, "referee", c)[0]) for h, s in zip(heur, ml)]
        m = metrics(labels, preds)
        if m["fp_rate"] > max_fpr:
            continue
        key = (m["recall"], m["f1"], c)  # ties -> higher cutoff (safer)
        if best is None or key > best[0]:
            best = (key, c, m)
    return best[1], best[2]


def run_modes(texts, labels, heur, ml, ref_cut):
    out, verdicts = {}, {}
    for mode in input_guard.MODES:
        vs = [input_guard.combine(h, s, mode, ref_cut)[0] for h, s in zip(heur, ml)]
        m = metrics(labels, [flagged(v) for v in vs])
        m["benign_blocked"] = sum(1 for y, v in zip(labels, vs) if not y and v == "blocked")
        m["benign_suspicious"] = sum(1 for y, v in zip(labels, vs) if not y and v == "suspicious")
        m["attacks_blocked"] = sum(1 for y, v in zip(labels, vs) if y and v == "blocked")
        out[mode], verdicts[mode] = m, vs
    return out, verdicts


def main():
    t0 = time.time()
    train, val, test, d12 = build_split()
    d17 = json.load(open(os.path.join(HERE, "day17_metrics.json")))
    sizes = {"train": len(train), "val": len(val), "test": len(test)}
    assert sizes == {k: d17["sizes"][k] for k in sizes}, f"split mismatch {sizes}"

    # Referee cutoff: train-only model, validation only.
    tx, ty = [t for t, _ in train], [y for _, y in train]
    l2 = d17["chosen"]["l2"]
    tm = detector_ml.TfidfLogReg(l2=l2, min_df=2).fit(tx, ty)
    vx, vy = [t for t, _ in val], [y for _, y in val]
    v_ml = [round(tm.predict_proba(t), 3) for t in vx]
    v_heur = [heur_verdict(t) for t in vx]
    ref_cut, val_m = pick_referee_cutoff(v_heur, v_ml, vy)
    val_modes, _ = run_modes(vx, vy, v_heur, v_ml, ref_cut)
    print(f"referee cutoff (validation) = {ref_cut}  {val_m}")

    # Measure once with the deployed model.
    model, ml_cut = detector_ml.load_saved_model()
    assert ml_cut == input_guard.OR_CUTOFF

    def score(texts):
        return [round(model.predict_proba(t), 3) for t in texts]

    res = {}
    # Day 12
    d_txt = [i["prompt"] for i in d12]
    d_y = [1 if i["label"] == "attack" else 0 for i in d12]
    d_h = [heur_verdict(t) for t in d_txt]
    d_ml = score(d_txt)
    res["day12"], d_v = run_modes(d_txt, d_y, d_h, d_ml, ref_cut)
    # deepset held-out test
    p_txt, p_y = [t for t, _ in test], [y for _, y in test]
    p_h = [heur_verdict(t) for t in p_txt]
    p_ml = score(p_txt)
    res["deepset_test"], _ = run_modes(p_txt, p_y, p_h, p_ml, ref_cut)

    # Disagreement table (Day 12): heuristics flag vs ML-alone flag at 0.43.
    rows = []
    for k, it in enumerate(d12):
        hf, mf = flagged(d_h[k]), d_ml[k] >= ml_cut
        if hf != mf:
            rows.append({"id": it["id"], "label": it["label"], "category": it["category"],
                         "heuristic_verdict": d_h[k],
                         "heuristic_score": round(max(input_guard.check_prompt(
                             it["prompt"], mode="heuristics")["scores"].values()), 3),
                         "ml_score": d_ml[k],
                         "final": {m: d_v[m][k] for m in input_guard.MODES}})
    out = {"seed": SEED, "sizes": sizes, "l2": l2, "or_cutoff": ml_cut,
           "referee_cutoff": ref_cut, "referee_cutoff_picked_on": "day17 validation split (train-only model)",
           "validation": val_modes, "results": res, "disagreements": rows,
           "runtime_s": round(time.time() - t0, 1)}
    with open(os.path.join(HERE, "day18_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print(json.dumps({"referee_cutoff": ref_cut, "results": res}, indent=1))
    for r in rows:
        print(r["id"], r["label"], r["heuristic_verdict"], r["heuristic_score"], r["ml_score"], r["final"])


if __name__ == "__main__":
    main()
