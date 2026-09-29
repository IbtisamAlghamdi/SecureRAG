#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase11_ablation_offline.py  --  item A-12
===================================================
The examiners asked for three things the thesis's ablation does not provide:
a leave-one-out row for every layer, the ablation run over all five seeds
rather than one, and a Full row for the same seed as the other rows.

Layers L0-L3 read only the query text. They perform no retrieval and invoke
no language model, so every configuration below is reproducible from the
generators alone. That is why this runs in minutes rather than the tens of
hours a generation-backed ablation would take: nothing here loads a model.

What it cannot produce is the Full (L0-L4) row and per-configuration latency,
both of which need generation. phase5 supplies those from the same batches.

Usage:
  python3 changeb4/phase11_ablation_offline.py --seeds 839 941 1049 1151 1279
"""
import argparse
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changeb4.common import make_batch, base_tier, save_csv, save_json  # noqa

CONFIGS = [
    ("L0_only",          dict(l1=False, l2=False, l3=False), "cumulative"),
    ("L0_L1",            dict(l1=True,  l2=False, l3=False), "cumulative"),
    ("L0_L1_L2",         dict(l1=True,  l2=True,  l3=False), "cumulative"),
    ("L0_L1_L2_L3",      dict(l1=True,  l2=True,  l3=True),  "cumulative"),
    ("without_L1",       dict(l1=False, l2=True,  l3=True),  "leave_one_out"),
    ("without_L2",       dict(l1=True,  l2=False, l3=True),  "leave_one_out"),
    ("without_L3",       dict(l1=True,  l2=True,  l3=False), "leave_one_out"),
]


def wilson(k, n):
    if n == 0:
        return (0.0, 0.0)
    from math import sqrt
    z = 1.959963985
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(100 * (c - h) / d, 2), round(100 * (c + h) / d, 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="*",
                    default=[839, 941, 1049, 1151, 1279])
    args = ap.parse_args()

    from changeb4.common import run_input_layers
    from src.config import settings

    print("=" * 74)
    print("A-12  ablation over the input layers -- no model, no retrieval")
    print("=" * 74)
    print("  seeds", args.seeds)
    print("  anomaly threshold", settings.get_anomaly_threshold())
    print("  b64 rule mode    ", getattr(settings, "get_b64_rule_mode", lambda: "n/a")())
    print("  zwsp mode        ", getattr(settings, "get_zwsp_mode", lambda: "n/a")())
    print()

    batches = {s: make_batch(s) for s in args.seeds}
    rows, summary = [], {}

    for name, flags, kind in CONFIGS:
        per_seed_asr, per_seed_fpr = [], []
        tot_a = tot_reached = tot_b = tot_bblocked = 0
        by_layer = {"L1": 0, "L2": 0, "L3": 0}
        by_cat = {}

        for seed in args.seeds:
            attacks, benign = batches[seed]
            a_reached = 0
            for a in attacks:
                r = run_input_layers(a["payload"], **flags)
                cat = base_tier(a["type"])
                d = by_cat.setdefault(cat, {"n": 0, "blocked": 0})
                d["n"] += 1
                if r["blocked_at"]:
                    by_layer[r["blocked_at"]] += 1
                    d["blocked"] += 1
                else:
                    a_reached += 1
            b_blocked = sum(1 for q in benign
                            if run_input_layers(q, **flags)["blocked_at"])
            na, nb = len(attacks), len(benign)
            per_seed_asr.append(100 * a_reached / na)
            per_seed_fpr.append(100 * b_blocked / nb)
            tot_a += na
            tot_reached += a_reached
            tot_b += nb
            tot_bblocked += b_blocked
            rows.append({"config": name, "kind": kind, "seed": seed,
                         "n_attacks": na, "reached": a_reached,
                         "asr_pct": round(100 * a_reached / na, 2),
                         "n_benign": nb, "benign_blocked": b_blocked,
                         "fpr_pct": round(100 * b_blocked / nb, 2)})

        summary[name] = {
            "kind": kind,
            "asr_pct_mean": round(statistics.mean(per_seed_asr), 2),
            "asr_pct_sd": round(statistics.pstdev(per_seed_asr), 2) if len(per_seed_asr) > 1 else 0.0,
            "asr_pooled_pct": round(100 * tot_reached / tot_a, 2),
            "asr_wilson95": wilson(tot_reached, tot_a),
            "fpr_pct_mean": round(statistics.mean(per_seed_fpr), 2),
            "fpr_pooled_pct": round(100 * tot_bblocked / tot_b, 2),
            "fpr_wilson95": wilson(tot_bblocked, tot_b),
            "blocks_by_layer": dict(by_layer),
            "n_attacks_pooled": tot_a, "n_benign_pooled": tot_b,
            "detection_by_category_pct": {
                c: round(100 * d["blocked"] / d["n"], 2) for c, d in sorted(by_cat.items())},
        }
        s = summary[name]
        print(f"  {name:<16s} ASR {s['asr_pooled_pct']:6.2f}%  "
              f"{str(s['asr_wilson95']):>16s}   FPR {s['fpr_pooled_pct']:5.2f}%   "
              f"L1 {by_layer['L1']:5d}  L2 {by_layer['L2']:5d}  L3 {by_layer['L3']:5d}")

    full4 = summary["L0_L1_L2_L3"]["asr_pooled_pct"]
    print()
    print("  marginal cost of removing one layer, against L0_L1_L2_L3:")
    for n in ("without_L1", "without_L2", "without_L3"):
        print(f"    {n:<12s} ASR {summary[n]['asr_pooled_pct']:6.2f}%   "
              f"{summary[n]['asr_pooled_pct'] - full4:+6.2f} points")

    save_csv(rows, "phase11", "A12_ablation_rows.csv")
    save_json({"seeds": args.seeds,
               "anomaly_threshold": settings.get_anomaly_threshold(),
               "b64_rule_mode": getattr(settings, "get_b64_rule_mode", lambda: "n/a")(),
               "zwsp_mode": getattr(settings, "get_zwsp_mode", lambda: "n/a")(),
               "configs": summary,
               "reading": ("L0_only blocks nothing by construction, so its ASR of "
                           "100% is structural rather than measured. Every other "
                           "row is a measurement. The Full (L0-L4) row needs "
                           "generation and comes from phase5.")},
              "phase11", "A12_ablation_summary.json")
    print("\n  saved -> Change-B4/phase11/")


if __name__ == "__main__":
    main()
