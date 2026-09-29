#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase9_l4_threshold.py  --  choosing L4's threshold without touching
an attack
==============================================================================
SEMANTIC_THRESHOLD = 0.18 was swept against similarities computed over the
whole index. Under L4_SCOPE="retrieved" the distribution is different, so the
value has to be chosen again -- and how it is chosen decides whether the result
survives the examiners' circularity objection (items 2 and 3).

The rule here: THE THRESHOLD IS CHOSEN FROM LEGITIMATE ANSWERS ONLY.

  * No attack, internal or external, takes any part in the choice. The
    threshold is a quantile of the similarity distribution of legitimate
    answers, so the operating false-positive rate is fixed by design rather
    than discovered by fitting against attacks.
  * The queries come from TUNING seeds (137, 271 by default), which are used
    for calibration and never for reporting. Final numbers are produced on the
    test seeds.
  * BIPIA is untouched, so the defended external run remains an independent
    test rather than a re-measurement of something already fitted.

This is also why the output reports several target rates instead of one: the
choice of how much legitimate traffic may be blocked is a deployment decision,
and the thesis should state it as one.

Cost: one generation per query, ~1.5 h for 300 queries.

Usage:
  python3 changeb4/phase9_l4_threshold.py --model Mistral-7B
  python3 changeb4/phase9_l4_threshold.py --model Mistral-7B --smoke
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import make_batch, save_csv, save_json, OUT_ROOT  # noqa: E402

TUNING_SEEDS_FOR_CALIBRATION = [137, 271]
TARGET_FPR = [0.001, 0.005, 0.01, 0.02, 0.05]


def threshold_for(sorted_neg, target):
    """Largest threshold whose observed false-positive rate stays <= target.

    Blocking is `sim < t`, so the count below t must not exceed target*n. With
    k = floor(target*n) allowed, the threshold sits just below the (k+1)-th
    smallest legitimate score.
    """
    n = len(sorted_neg)
    k = int(np.floor(target * n))
    if k >= n:
        return None
    t = sorted_neg[k] - 1e-6
    blocked = sum(1 for v in sorted_neg if v < t)
    return {"target_fpr": target, "threshold": round(float(t), 4),
            "observed_fpr": round(blocked / n, 4), "blocked": blocked, "n": n}


def wilson(x, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = x / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z / d * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(float(max(0.0, 100 * (c - h))), 3), round(float(100 * (c + h)), 3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Mistral-7B")
    ap.add_argument("--seeds", type=int, nargs="*",
                    default=TUNING_SEEDS_FOR_CALIBRATION)
    ap.add_argument("--per-seed", type=int, default=150)
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    if args.smoke:
        args.per_seed, args.seeds = 3, args.seeds[:1]

    from src.config import settings
    from model_select import resolve_model
    resolve_model(args.model)
    from src.pipeline import SecureRAG

    queries = []
    for sd in args.seeds:
        _, benign = make_batch(sd)
        queries += [(sd, q) for q in benign[:args.per_seed]]
    print("=" * 74)
    print("L4 threshold calibration -- legitimate answers only, no attacks")
    print("=" * 74)
    print(f"  calibration seeds {args.seeds}  (tuning seeds; never reported on)")
    print(f"  legitimate queries {len(queries)}")
    print(f"  scope in effect    {settings.get_l4_scope()}")

    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
    E = np.asarray(rag.retriever.get_embeddings(), dtype="float32")
    En = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-10)
    print(f"  index              {E.shape[0]} chunks\n")

    rows, t0 = [], time.time()
    for i, (sd, q) in enumerate(queries, 1):
        res = rag.run(q)
        resp = res.get("response") or ""
        blocked = res.get("flag") not in ("clean", "baseline", "error")
        if blocked or not resp:
            rows.append({"seed": sd, "query": q[:160], "blocked_by_pipeline": blocked,
                         "sim_corpus": "", "sim_retrieved": "", "n_retrieved": 0})
        else:
            a = rag.embedder.encode(resp)
            a = a / (np.linalg.norm(a) + 1e-10)
            idx = getattr(rag, "_last_retrieved_idx", []) or []
            rows.append({
                "seed": sd, "query": q[:160], "blocked_by_pipeline": False,
                "sim_corpus": round(float(np.max(En @ a)), 4),
                "sim_retrieved": (round(float(np.max(En[idx] @ a)), 4)
                                  if idx else ""),
                "n_retrieved": len(idx),
            })
        if i == 1 or i % 10 == 0 or i == len(queries):
            el = time.time() - t0
            print(f"  {i}/{len(queries)}  ({el/i:.1f}s/q, "
                  f"~{(len(queries)-i)*el/i/60:.0f} min left)", flush=True)

    save_csv(rows, "phase9", "L4_threshold_calibration_rows.csv")

    out = {"model": args.model, "calibration_seeds": args.seeds,
           "n_queries": len(queries),
           "n_blocked_by_pipeline": sum(1 for r in rows if r["blocked_by_pipeline"]),
           "index_chunks": int(E.shape[0]),
           "deployed_threshold": settings.get_semantic_threshold(),
           "rule": "threshold is a quantile of legitimate-answer similarity; "
                   "no attack takes part in the choice",
           "variants": {}}

    for key, col in (("corpus", "sim_corpus"), ("retrieved", "sim_retrieved")):
        vals = sorted(float(r[col]) for r in rows if str(r[col]).strip())
        if not vals:
            continue
        q = lambda p: round(float(np.percentile(vals, p)), 4)
        out["variants"][key] = {
            "n": len(vals), "min": round(vals[0], 4), "max": round(vals[-1], 4),
            "mean": round(float(np.mean(vals)), 4),
            "percentiles": {"p0.5": q(0.5), "p1": q(1), "p2": q(2),
                            "p5": q(5), "p25": q(25), "p50": q(50)},
            "thresholds": [t for t in (threshold_for(vals, f) for f in TARGET_FPR)
                           if t],
            "at_deployed_0_18": {
                "blocked": sum(1 for v in vals if v < settings.SEMANTIC_THRESHOLD),
                "fpr": round(sum(1 for v in vals
                                 if v < settings.SEMANTIC_THRESHOLD) / len(vals), 4),
            },
        }
        for t in out["variants"][key]["thresholds"]:
            t["wilson95_fpr"] = wilson(t["blocked"], t["n"])

    # Informational only: what these thresholds would have caught on the
    # phase 8 positives. Reported AFTER the choice, never used to make it.
    p8 = OUT_ROOT / "phase8" / "A9_l4_comparison.json"
    if p8.exists():
        try:
            import csv as _csv
            _csv.field_size_limit(10_000_000)
            pr = OUT_ROOT / "phase8" / "A9_l4_comparison_rows.csv"
            pos = [r for r in _csv.DictReader(open(pr, encoding="utf-8-sig"))
                   if r["group"] == "positive"]
            for key, col in (("corpus", "sim_corpus"), ("retrieved", "sim_retrieved")):
                if key not in out["variants"]:
                    continue
                ps = [float(r[col]) for r in pos]
                for t in out["variants"][key]["thresholds"]:
                    t["recall_on_phase8_positives"] = round(
                        sum(1 for v in ps if v < t["threshold"]) / max(len(ps), 1), 4)
            out["recall_note"] = ("recall is reported as a consequence of a "
                                  "threshold chosen from legitimate answers; it "
                                  "played no part in choosing it")
        except Exception as e:
            out["recall_note"] = f"phase8 read failed: {e}"

    save_json(out, "phase9", "L4_threshold_calibration.json")

    print("\n" + "=" * 74)
    for key in ("corpus", "retrieved"):
        v = out["variants"].get(key)
        if not v:
            continue
        print(f"\n  {key.upper()}   n={v['n']}  mean={v['mean']}  min={v['min']}")
        print(f"    at the deployed 0.18: FPR {v['at_deployed_0_18']['fpr']}")
        print(f"    {'target':>8}{'threshold':>11}{'obs FPR':>10}"
              f"{'Wilson95 %':>16}{'recall*':>10}")
        for t in v["thresholds"]:
            print(f"    {t['target_fpr']:>8}{t['threshold']:>11}"
                  f"{t['observed_fpr']:>10}"
                  f"{str(t.get('wilson95_fpr','')):>16}"
                  f"{str(t.get('recall_on_phase8_positives','--')):>10}")
    print("\n  * recall is a consequence of the choice, not an input to it.")
    print("  saved -> Change-B4/phase9/")


if __name__ == "__main__":
    main()
