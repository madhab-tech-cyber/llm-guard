"""LLM Guard - Member 2 - Input Guard
Day 17: train and evaluate the ML injection classifier properly.

Run: python3 day17_train_eval.py        (no pip install, ~3-4 min)

What it does
1. Loads the data:
   - day17_public_deepset.json : public dataset deepset/prompt-injections
     (Hugging Face, Apache-2.0, 546 train + 116 test rows, English+German).
   - day16_train_set.json      : our 80 hand-written synthetic seed prompts.
   - day12_test_set.json       : our 100-prompt Day 12 test set. EVAL ONLY.
2. Leakage checks: drops any training/validation/test prompt that is an
   exact or near duplicate (word-set Jaccard >= 0.8) of a Day 12 prompt,
   and drops training prompts that duplicate the held-out test.
3. Split (fixed seed 17):
   - TEST       = deepset's own "test" split (116), never used for choosing.
   - TRAIN/VAL  = deepset "train" (546) + seed (80), shuffled, 80% / 20%.
4. Picks settings on VALIDATION only (L2 strength + score cutoff, with the
   cutoff chosen as the highest-recall one whose validation FP rate <= 5%).
5. Refits on TRAIN+VAL with the chosen settings, saves day17_model.json,
   and reports numbers ONCE on TEST and on the Day 12 set, next to the
   heuristics. Writes everything to day17_metrics.json.
"""
import json
import os
import random
import re
import time

import detector_ml
import input_guard

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 17
WORD = re.compile(r"[a-z0-9']+")


def norm(t):
    return " ".join(t.lower().split())


def wset(t):
    return set(WORD.findall(t.lower()))


def jaccard(a, b):
    return len(a & b) / len(a | b) if (a or b) else 1.0


def metrics(labels, preds):
    tp = sum(1 for y, p in zip(labels, preds) if y and p)
    fp = sum(1 for y, p in zip(labels, preds) if not y and p)
    fn = sum(1 for y, p in zip(labels, preds) if y and not p)
    tn = sum(1 for y, p in zip(labels, preds) if not y and not p)
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": round(rec, 3),
            "precision": round(prec, 3), "f1": round(f1, 3), "fp_rate": round(fpr, 3)}


def pick_cutoff(scores, labels, max_fpr=0.05):
    best = None
    for c in [x / 100 for x in range(5, 96)]:
        m = metrics(labels, [s >= c for s in scores])
        if m["fp_rate"] <= max_fpr and (best is None or m["recall"] > best[1]["recall"]
                                       or (m["recall"] == best[1]["recall"] and m["f1"] > best[1]["f1"])):
            best = (c, m)
    return best


def main():
    t_start = time.time()
    pub = json.load(open(os.path.join(HERE, "day17_public_deepset.json"), encoding="utf-8"))
    seed_t, seed_y = detector_ml.load_training_set()
    d12 = json.load(open(os.path.join(HERE, "day12_test_set.json"), encoding="utf-8"))["items"]
    d12_norm = {norm(i["prompt"]) for i in d12}
    d12_sets = [wset(i["prompt"]) for i in d12]

    def near_d12(t):
        if norm(t) in d12_norm:
            return True
        s = wset(t)
        return any(jaccard(s, x) >= 0.8 for x in d12_sets)

    leak = {"dropped_near_day12": 0, "dropped_train_dup_of_test": 0, "dropped_dup_within": 0}
    test = []
    for r in pub["test"]:
        if near_d12(r["text"]):
            leak["dropped_near_day12"] += 1
            continue
        test.append((r["text"], int(r["label"])))
    test_norm = {norm(t) for t, _ in test}

    pool, seen = [], set()
    for t, y in [(r["text"], int(r["label"])) for r in pub["train"]] + list(zip(seed_t, seed_y)):
        n = norm(t)
        if near_d12(t):
            leak["dropped_near_day12"] += 1
            continue
        if n in test_norm:
            leak["dropped_train_dup_of_test"] += 1
            continue
        if n in seen:
            leak["dropped_dup_within"] += 1
            continue
        seen.add(n)
        pool.append((t, y))
    random.Random(SEED).shuffle(pool)
    cut = int(0.8 * len(pool))
    train, val = pool[:cut], pool[cut:]

    # Final leak re-check: nothing in train/val/test equals a Day 12 prompt.
    all_used = [t for t, _ in train + val + test]
    leak["remaining_exact_day12"] = sum(1 for t in all_used if norm(t) in d12_norm)
    leak["remaining_train_in_test"] = sum(1 for t, _ in train + val if norm(t) in test_norm)

    tx, ty = [t for t, _ in train], [y for _, y in train]
    vx, vy = [t for t, _ in val], [y for _, y in val]
    grid = []
    for l2 in (0.0001, 0.001, 0.01):
        m = detector_ml.TfidfLogReg(l2=l2, min_df=2).fit(tx, ty)
        vs = [m.predict_proba(t) for t in vx]
        c, vm = pick_cutoff(vs, vy)
        grid.append({"l2": l2, "cutoff": c, "val": vm})
        print(f"val  l2={l2:<7} cutoff={c:.2f}  {vm}")
    best = max(grid, key=lambda g: (g["val"]["recall"], g["val"]["f1"]))

    # Refit on train+val with the chosen settings; evaluate ONCE.
    fx, fy = tx + vx, ty + vy
    final = detector_ml.TfidfLogReg(l2=best["l2"], min_df=2).fit(fx, fy)
    cutoff = best["cutoff"]
    ts = [final.predict_proba(t) for t, _ in test]
    test_m = metrics([y for _, y in test], [s >= cutoff for s in ts])
    # Same held-out test, heuristics only (for a fair side-by-side).
    test_heur = metrics([y for _, y in test],
                        [input_guard.check_prompt(t)["verdict"] != "clean" for t, _ in test])

    # Day 12 set: ML alone, heuristics alone, and injection-type attacks only.
    inj_cats = ("direct-injection", "jailbreak-roleplay", "indirect")
    d12_y = [1 if i["label"] == "attack" else 0 for i in d12]
    ml_s = [final.predict_proba(i["prompt"]) for i in d12]
    heur_flag = [input_guard.check_prompt(i["prompt"])["verdict"] != "clean" for i in d12]
    ml_flag = [s >= cutoff for s in ml_s]
    sub = [k for k, i in enumerate(d12) if i["label"] == "benign"
           or i["category"] in inj_cats or i["category"].startswith("encoded")]
    def on(idx, flags):
        return metrics([d12_y[k] for k in idx], [flags[k] for k in idx])
    allidx = list(range(len(d12)))
    either = [a or b for a, b in zip(heur_flag, ml_flag)]
    day12 = {
        "heuristics_all50": on(allidx, heur_flag),
        "ml_all50": on(allidx, ml_flag),
        "heuristics_or_ml_all50": on(allidx, either),
        "heuristics_injection_subset": on(sub, heur_flag),
        "ml_injection_subset": on(sub, ml_flag),
        "ml_false_positives": [d12[k]["id"] for k in allidx if not d12_y[k] and ml_flag[k]],
        "ml_catches_heuristic_misses": [d12[k]["id"] for k in allidx
                                        if d12_y[k] and ml_flag[k] and not heur_flag[k]],
        "ml_misses": [d12[k]["id"] for k in allidx if d12_y[k] and not ml_flag[k]],
    }
    model = {"version": "day17", "l2": best["l2"], "lr": final.lr, "epochs": final.epochs,
             "min_df": final.min_df, "cutoff": cutoff, "bias": round(final.bias, 6),
             "idf": {f: round(v, 5) for f, v in final.idf.items()},
             "weights": {f: round(v, 6) for f, v in final.weights.items()},
             "trained_on": {"rows": len(fx), "attacks": sum(fy)},
             "sources": pub["source"]}
    with open(os.path.join(HERE, "day17_model.json"), "w", encoding="utf-8") as fh:
        json.dump(model, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    out = {"seed": SEED, "sizes": {"train": len(train), "val": len(val), "test": len(test),
                                   "train_attacks": sum(ty), "val_attacks": sum(vy),
                                   "test_attacks": sum(y for _, y in test)},
           "leakage": leak, "grid": grid, "chosen": {"l2": best["l2"], "cutoff": cutoff},
           "test": test_m, "test_heuristics": test_heur, "day12": day12,
           "runtime_s": round(time.time() - t_start, 1)}
    with open(os.path.join(HERE, "day17_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
