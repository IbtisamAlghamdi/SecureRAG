#!/usr/bin/env python3
"""threshold_sensitivity_analysis.py ----------------------------------- Post-hoc sensitivity."""

import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def load(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))

def run():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fpr", required=True, help="run_external_fpr_eval.py results CSV")
    parser.add_argument("--attack", required=True, help="run_external_eval.py results CSV")
    parser.add_argument("--thresholds", type=float, nargs="+",
                         default=[0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45],
                         help="Candidate SEMANTIC_THRESHOLD values to test (default: 0.15-0.45)")
    parser.add_argument("--out-prefix", default="threshold_sensitivity",
                         help="Prefix for the output CSV/PNG (default: threshold_sensitivity)")
    args = parser.parse_args()

    fpr_rows = load(args.fpr)
    atk_rows = load(args.attack)

    n_benign_total = len(fpr_rows)
    n_attack_total = len(atk_rows)

    benign_already_blocked = sum(1 for r in fpr_rows
                                  if r.get("false_positive") == "True")
    attack_already_blocked = sum(1 for r in atk_rows
                                  if r.get("blocked") == "True")

    benign_l4 = [float(r["similarity_score"]) for r in fpr_rows if r.get("similarity_score")]
    attack_l4 = [float(r["similarity_score"]) for r in atk_rows if r.get("similarity_score")]

    if not benign_l4 or not attack_l4:
        print("No similarity_score data found in one or both files -- re-run "
              "run_external_eval.py / run_external_fpr_eval.py with the current "
              "pipeline.py (l4_checked/similarity_score) first.")
        return

    print(f"Benign: {n_benign_total} total, {benign_already_blocked} already "
          f"blocked pre-L4, {len(benign_l4)} reached L4 with a score")
    print(f"Attack: {n_attack_total} total, {attack_already_blocked} already "
          f"blocked pre-L4, {len(attack_l4)} reached L4 with a score\n")

    header = f"{'threshold':>9} | {'L4 FPR':>10} | {'overall FPR':>12} | {'L4 recovered':>13} | {'overall ASR':>12}"
    print(header)
    print("-" * len(header))

    rows_out = []
    for thr in sorted(args.thresholds):
        l4_fp = sum(1 for s in benign_l4 if s < thr)
        l4_caught = sum(1 for s in attack_l4 if s < thr)
        total_fp = benign_already_blocked + l4_fp
        total_blocked_attacks = attack_already_blocked + l4_caught
        overall_fpr = 100 * total_fp / n_benign_total
        overall_asr = 100 * (n_attack_total - total_blocked_attacks) / n_attack_total
        l4_fpr_pct = 100 * l4_fp / len(benign_l4)
        l4_recover_pct = 100 * l4_caught / len(attack_l4)

        print(f"{thr:>9.2f} | {l4_fpr_pct:>8.1f}%  | {overall_fpr:>10.2f}%  | "
              f"{l4_recover_pct:>11.1f}%  | {overall_asr:>10.2f}%")

        rows_out.append({
            "threshold": thr,
            "l4_fp_count": l4_fp, "l4_fp_pool": len(benign_l4), "l4_fpr_pct": round(l4_fpr_pct, 2),
            "overall_fpr_pct": round(overall_fpr, 2),
            "l4_recovered_count": l4_caught, "l4_recovered_pool": len(attack_l4),
            "l4_recovered_pct": round(l4_recover_pct, 2),
            "overall_asr_pct": round(overall_asr, 2),
        })

    out_csv = f"{args.out_prefix}.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        writer.writeheader()
        writer.writerows(rows_out)
    print(f"\nTable saved -> {out_csv}")

    # ── Trade-off chart ──────────────────────────────────────────────────
    thrs = [r["threshold"] for r in rows_out]
    fprs = [r["overall_fpr_pct"] for r in rows_out]
    asrs = [r["overall_asr_pct"] for r in rows_out]

    fig, ax1 = plt.subplots(figsize=(8, 5.5))
    ax1.set_xlabel("SEMANTIC_THRESHOLD (L4)")
    ax1.set_ylabel("Overall FPR (%)", color="#c0392b")
    l1, = ax1.plot(thrs, fprs, "o-", color="#c0392b", label="FPR (%)")
    ax1.tick_params(axis="y", labelcolor="#c0392b")

    ax2 = ax1.twinx()
    ax2.set_ylabel("Overall ASR (%)", color="#2c3e50")
    l2, = ax2.plot(thrs, asrs, "s--", color="#2c3e50", label="ASR (%)")
    ax2.tick_params(axis="y", labelcolor="#2c3e50")

    ax1.axvline(0.15, color="gray", ls=":", alpha=0.6)
    ax1.annotate("current (0.15)", xy=(0.15, ax1.get_ylim()[1]*0.9),
                 fontsize=8, color="gray", rotation=90, va="top")

    plt.title("SEMANTIC_THRESHOLD sensitivity: FPR/ASR trade-off\n"
              f"(BIPIA external, n={n_benign_total} benign / {n_attack_total} attack)")
    fig.legend(handles=[l1, l2], loc="upper center", bbox_to_anchor=(0.5, 0.02), ncol=2)
    plt.tight_layout()
    out_png = f"{args.out_prefix}.png"
    plt.savefig(out_png, dpi=150, bbox_inches="tight")
    print(f"Chart saved  -> {out_png}")


if __name__ == "__main__":
    run()
