#!/usr/bin/env python3
"""
l3_threshold_sensitivity.py
-----------------------------
Sensitivity analysis for ANOMALY_THRESHOLD (L3), the direct counterpart to
threshold_sensitivity_analysis.py's sweep of SEMANTIC_THRESHOLD (L4).

WHY this exists (Reviewer concern: "threshold choices insufficiently
justified, no sensitivity analysis"): settings.ANOMALY_THRESHOLD = 15.0 is
the scale anchor for three separate decisions --

    L0 risk class : score > 15.0*1.8 = 27.0 -> HIGH
                    score > 15.0*1.0 = 15.0 -> MEDIUM
    L3 block bar  : score > 2.0 * (15.0 * 0.7 if L0 said HIGH else 15.0)
                    i.e. 21.0 for HIGH-risk queries, 30.0 otherwise

-- and unlike SEMANTIC_THRESHOLD it has never been swept. This script
produces that sweep.

It needs NO language model and NO retrieval index: L0-L3 inspect the input
only, so the entire attack/benign decision for those layers is reproducible
from the generators alone. That is what makes this analysis cheap enough to
run for every candidate value rather than argued from a single point.

Both sides are swept together -- attacks (detection) and benign queries
(false positives) -- so the trade-off at each candidate is visible in one
table instead of being tuned against one side.

Usage:
    conda activate RAG
    python3 l3_threshold_sensitivity.py                 # seed 42, 1001+333
    python3 l3_threshold_sensitivity.py --seeds 42 137 271 413 509
"""

import argparse
import json
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.defenses.sanitization.sanitize import sanitize_input, get_sanitization_report
from src.defenses.rules.rule_filter import rule_based_detector_detailed, quick_high_risk_scan
from src.defenses.anomaly.anomaly_detector import compute_anomaly_score
from src.attacks.generator import RealisticAttackGenerator

SCRIPT_DIR = Path(__file__).parent

def decide(query, thr):
    """Replays pipeline.run()'s L0-L3 sequence with ANOMALY_THRESHOLD = thr."""
    if quick_high_risk_scan(query):
        risk = "HIGH"
    else:
        s = compute_anomaly_score(query)
        risk = "HIGH" if s > thr * 1.8 else "MEDIUM" if s > thr * 1.0 else "LOW"

    sq = sanitize_input(query)
    rep = get_sanitization_report(query, sq)
    if rep["had_template_inj"] or rep["had_injection"] or rep["had_base64"]:
        return "L1", risk
    if rule_based_detector_detailed(sq)[0]:
        return "L2", risk

    score = compute_anomaly_score(query)
    if score > 2.0 * (thr * (0.7 if risk == "HIGH" else 1.0)):
        return "L3", risk
    return None, risk

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, nargs="+", default=[42])
    ap.add_argument("--attacks", type=int, default=1001)
    ap.add_argument("--benign", type=int, default=333)
    ap.add_argument("--thresholds", type=float, nargs="+",
                    default=[5.0, 7.5, 10.0, 12.5, 15.0, 17.5, 20.0, 25.0, 30.0])
    ap.add_argument("--external-fpr", default="fpr_set.json",
                    help="BIPIA benign set (fpr_set.json). This is the side "
                         "that matters: the internal benign generator produces "
                         "short user-written queries that barely reach L3, "
                         "whereas the BIPIA benign documents are long, dense "
                         "and are where L3's only observed false positives "
                         "actually occur. Pass '' to skip.")
    args = ap.parse_args()

    print(f"Generating {args.attacks} attacks + {args.benign} benign per seed "
          f"{args.seeds} (no model needed -- L0-L3 inspect input only)\n")
    atk, ben = [], []
    for sd in args.seeds:
        random.seed(sd)
        g = RealisticAttackGenerator()
        atk += [a["payload"] for a in g.generate_batch(args.attacks, benign_ratio=0.0)
                if a.get("is_attack", True)][:args.attacks]
        random.seed(sd)
        ben += RealisticAttackGenerator().generate_benign_batch(args.benign)
    print(f"  {len(atk)} attacks, {len(ben)} benign\n")

    ext = []
    if args.external_fpr and Path(args.external_fpr).exists():
        ext = [x["combined_query"] for x in json.load(open(args.external_fpr, encoding="utf-8"))]
        print(f"  {len(ext)} external BIPIA benign documents "
              f"({args.external_fpr}) -- every block on these is by "
              f"definition a false positive\n")
    else:
        print(f"  (no external benign set at {args.external_fpr!r} -- "
              f"external columns skipped)\n")

    rows = []
    for thr in args.thresholds:
        a_layers = [decide(q, thr)[0] for q in atk]
        b_layers = [decide(q, thr)[0] for q in ben]
        blocked = sum(1 for x in a_layers if x)
        l3 = sum(1 for x in a_layers if x == "L3")
        fp = sum(1 for x in b_layers if x)
        fp_l3 = sum(1 for x in b_layers if x == "L3")
        e_layers = [decide(q, thr)[0] for q in ext] if ext else []
        e_fp = sum(1 for x in e_layers if x)
        e_fp_l3 = sum(1 for x in e_layers if x == "L3")
        rows.append(dict(threshold=thr, detection=100*blocked/len(atk),
                         l3_blocks=l3, fpr=100*fp/len(ben), fp_l3=fp_l3,
                         blocked=blocked, fp=fp,
                         ext_fpr=(100*e_fp/len(ext) if ext else None),
                         ext_fp=e_fp if ext else None,
                         ext_fp_l3=e_fp_l3 if ext else None))

    hdr = (f"{'ANOMALY':>9} {'pre-L4 det':>11} {'L3 blocks':>10} "
           f"{'internal FPR':>13} {'external FPR':>13} {'ext L3 FPs':>11}")
    print(hdr); print("-" * len(hdr))
    for r in rows:
        star = "  <-- shipped" if r["threshold"] == 15.0 else ""
        e = f"{r['ext_fpr']:>12.2f}%" if r['ext_fpr'] is not None else f"{'--':>13}"
        el = f"{r['ext_fp_l3']:>11d}" if r['ext_fp_l3'] is not None else f"{'--':>11}"
        print(f"{r['threshold']:>9.1f} {r['detection']:>10.2f}% {r['l3_blocks']:>10d} "
              f"{r['fpr']:>12.2f}% {e} {el}{star}")

    out = SCRIPT_DIR / "l3_threshold_sensitivity.json"
    json.dump({"seeds": args.seeds, "n_attacks": len(atk), "n_benign": len(ben),
               "rows": rows}, open(out, "w"), indent=2)
    print(f"\nSaved -> {out}")

    fig, ax = plt.subplots(figsize=(8, 5))
    t = [r["threshold"] for r in rows]
    ax.plot(t, [r["detection"] for r in rows], "o-", color="#2f4858",
            label="pre-L4 detection (attacks)")
    ax.plot(t, [r["fpr"] for r in rows], "s-", color="#a44a3f",
            label="internal FPR (generated benign queries)")
    if rows[0]["ext_fpr"] is not None:
        ax.plot(t, [r["ext_fpr"] for r in rows], "^-", color="#c98a3f",
                label="external FPR (BIPIA benign documents)")
    ax.axvline(15.0, ls="--", color="#888", lw=1)
    ax.annotate("shipped\n15.0", xy=(15.0, 50), ha="center", fontsize=9, color="#555")
    ax.set_xlabel("ANOMALY_THRESHOLD"); ax.set_ylabel("%")
    ax.set_title(f"L3 threshold sensitivity — L0–L3 only, "
                 f"n={len(atk)} attacks / {len(ben)} benign", fontweight="bold", fontsize=11)
    ax.legend(); ax.grid(alpha=0.3)
    plt.tight_layout()
    png = SCRIPT_DIR / "l3_threshold_sensitivity.png"
    fig.savefig(png, dpi=150, bbox_inches="tight")
    print(f"Chart -> {png}")


if __name__ == "__main__":
    main()
