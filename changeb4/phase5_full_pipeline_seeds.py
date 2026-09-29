#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase5_full_pipeline_seeds.py  --  items A-3, A-12, A-10
=================================================================
Three things the offline phases cannot produce because they need L4 and the
model, and which the examiners asked for explicitly:

A-3   final results on seeds never used for tuning, through the COMPLETE
      pipeline -- phase 0 only reaches L3.
A-12  the seed-42 Full row (the thesis mixes one seed with a five-seed mean),
      and the same ablation run over every seed.
A-10  McNemar applied between two configurations that actually differ --
      L0-L3 versus Full, paired per query -- instead of against a baseline
      whose c = 0 is true by construction.

One pass produces all three: each query is run once through the full pipeline
and the L4 decision is recorded separately, so the L0-L3 configuration is
read off the same run rather than requiring a second one.

Cost: queries blocked before generation are ~1 ms; only those reaching the
model cost a generation. About 30 min per seed on an M4 Air.

Usage:
  python3 changeb4/phase5_full_pipeline_seeds.py --model Mistral-7B --seeds 42 613 727
"""
import argparse
import math
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import make_batch, base_tier, save_csv, save_json  # noqa


def mcnemar(b, c):
    """Paired test between two configurations. b = blocked by Full but not by
    L0-L3, c = the reverse (structurally zero here, but computed rather than
    assumed)."""
    if b + c == 0:
        return {"b": b, "c": c, "chi2": None, "p_lt_0_001": False,
                "note": "no discordant pairs"}
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    return {"b": b, "c": c, "chi2": round(chi2, 2),
            "p_lt_0_001": chi2 > 10.83,
            "note": "continuity-corrected McNemar on discordant pairs"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Mistral-7B")
    ap.add_argument("--seeds", type=int, nargs="*", default=[42, 613, 727])
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    from src.config import settings
    from model_select import resolve_model
    resolve_model(args.model)
    from src.pipeline import SecureRAG

    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
    rows, per_seed = [], {}

    for seed in args.seeds:
        attacks, benign = make_batch(seed)
        if args.limit:
            attacks, benign = attacks[:args.limit], benign[:max(args.limit // 3, 1)]
        print(f"\n--- seed {seed}: {len(attacks)} attacks + {len(benign)} benign")
        t0 = time.time()
        a_full = a_pre = 0
        b_full = b_pre = 0
        lat_attack, lat_benign = [], []
        disc_b = disc_c = 0

        for i, a in enumerate(attacks, 1):
            res = rag.run(a["payload"])
            layer = res.get("layer", "none")
            blocked_full = res.get("flag") not in ("clean", "baseline", "error")
            blocked_pre = blocked_full and layer != "semantic"
            a_full += blocked_full
            a_pre += blocked_pre
            if blocked_full and not blocked_pre:
                disc_b += 1
            if blocked_pre and not blocked_full:
                disc_c += 1
            lat_attack.append(res.get("latency", 0.0))
            rows.append({"seed": seed, "kind": "attack", "category": base_tier(a["type"]),
                         "blocked_full": blocked_full, "blocked_pre_l4": blocked_pre,
                         "layer": layer, "risk": res.get("risk", ""),
                         "anomaly_score": res.get("anomaly_score", ""),
                         "l4_checked": res.get("l4_checked", ""),
                         "similarity_score": res.get("similarity_score", ""),
                         "latency": res.get("latency", "")})
            if i == 1 or i % 50 == 0 or i == len(attacks):
                el = time.time() - t0
                print(f"    attacks {i}/{len(attacks)} ({el/i:.2f}s/q, "
                      f"~{(len(attacks)-i)*el/i/60:.0f} min left)", flush=True)

        for q in benign:
            res = rag.run(q)
            layer = res.get("layer", "none")
            blocked_full = res.get("flag") not in ("clean", "baseline", "error")
            blocked_pre = blocked_full and layer != "semantic"
            b_full += blocked_full
            b_pre += blocked_pre
            lat_benign.append(res.get("latency", 0.0))
            rows.append({"seed": seed, "kind": "benign", "category": "benign",
                         "blocked_full": blocked_full, "blocked_pre_l4": blocked_pre,
                         "layer": layer, "risk": res.get("risk", ""),
                         "anomaly_score": res.get("anomaly_score", ""),
                         "l4_checked": res.get("l4_checked", ""),
                         "similarity_score": res.get("similarity_score", ""),
                         "latency": res.get("latency", "")})

        na, nb = len(attacks), len(benign)
        per_seed[seed] = {
            "n_attacks": na, "n_benign": nb,
            "ASR_full_pct": round(100 * (na - a_full) / na, 2),
            "ASR_L0_L3_pct": round(100 * (na - a_pre) / na, 2),
            "FPR_full_pct": round(100 * b_full / nb, 2),
            "FPR_L0_L3_pct": round(100 * b_pre / nb, 2),
            "L4_marginal_blocks": a_full - a_pre,
            "latency_attacks_mean_s": round(statistics.mean(lat_attack), 3),
            "latency_benign_mean_s": round(statistics.mean(lat_benign), 3),
            "mcnemar_L0L3_vs_Full": mcnemar(disc_b, disc_c),
        }
        p = per_seed[seed]
        print(f"    ASR  L0-L3 {p['ASR_L0_L3_pct']}%  ->  Full {p['ASR_full_pct']}%"
              f"   (L4 adds {p['L4_marginal_blocks']} blocks)")
        print(f"    FPR  L0-L3 {p['FPR_L0_L3_pct']}%  ->  Full {p['FPR_full_pct']}%")
        print(f"    latency  attacks {p['latency_attacks_mean_s']}s | "
              f"legitimate {p['latency_benign_mean_s']}s")
        print(f"    McNemar L0-L3 vs Full: {p['mcnemar_L0L3_vs_Full']}")
        print(f"    seed done in {(time.time()-t0)/60:.1f} min")

    # The canonical names are kept so anything reading the fixed path still
    # works, but every run also writes a stamped copy. Three invocations of
    # this script (Mistral, temperature 0, Llama) share one output directory,
    # and without the stamp the last one silently overwrites the others.
    tag = args.model.replace("/", "_")
    _t = os.environ.get("SECURERAG_TEMPERATURE", "").strip()
    if _t:
        tag += "_temp" + _t.replace(".", "p")
    save_csv(rows, "phase5", f"rows_{tag}.csv")
    save_csv(rows, "phase5", "A3_A12_full_pipeline_rows.csv")
    summary = {"model": args.model, "seeds": args.seeds, "per_seed": per_seed}
    if len(args.seeds) > 1:
        summary["mean_ASR_full_pct"] = round(
            statistics.mean(p["ASR_full_pct"] for p in per_seed.values()), 2)
        summary["mean_FPR_full_pct"] = round(
            statistics.mean(p["FPR_full_pct"] for p in per_seed.values()), 2)
    summary["reading"] = (
        "ASR_L0_L3 and ASR_full come from the SAME run, so the pair is exact "
        "rather than a comparison of two separate runs. Seeds other than 42 "
        "were never used for threshold tuning (item A-3).")
    save_json(summary, "phase5", f"summary_{tag}.json")
    save_json(summary, "phase5", "A3_A12_A10_summary.json")
    print("\nPhase 5 complete.")


if __name__ == "__main__":
    main()
