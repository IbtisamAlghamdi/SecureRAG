#!/usr/bin/env python3
"""
measure_layer_effectiveness.py
---------------------------------
Direct, per-query measurement of which layer actually blocked each
attack -- NOT a derived/estimated number. Runs the SAME internal attack
batch thesis_evaluation.py's Run 1 uses (RealisticAttackGenerator,
seed=42, 1,001 attacks -- same seed as the confusion matrix, so both
charts describe the exact same run) through the real SecureRAG pipeline,
and tallies res['layer'] directly for every single query, the same way
run_external_eval.py already tallies layer_counts for the external run.

WHY this exists instead of just reusing the ablation study's cumulative
deltas: the deltas (blocked(L0+L1) - blocked(L0), etc.) are real and
already verified, but they are an INDIRECT computation -- this script
gives the DIRECT, per-query answer instead, so "Defense Layer
Effectiveness" is an actual measurement, not an inference from another
chart's numbers.

Usage:
    conda activate RAG
    python3 measure_layer_effectiveness.py --model Mistral-7B
    (optional: --seed 42 to match a different Run's seed, --attacks 1001)

Output:
    layer_effectiveness__<model>.json  -- read directly by
    generate_final_charts.py's chart_layer_effectiveness() (it prefers
    this real file over the derived-delta fallback when present).
"""

import argparse
import json
import os
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.config import settings
from src.pipeline import SecureRAG
from src.attacks.generator import RealisticAttackGenerator
from model_select import add_model_arg, resolve_model, safe_filename

SCRIPT_DIR = Path(__file__).parent

# Maps pipeline.py's res['layer'] values to the 4 defense-layer buckets
# this chart reports. "none" (reached the model, not blocked by L1-L4)
# is tracked separately -- it is NOT an "L4 miss", it just means nothing
# blocked it (L4 checked and found nothing suspicious, or wasn't run).
LAYER_BUCKETS = {
    "template_injection": "L1", "sanitization": "L1",
    "rules": "L2",
    "anomaly": "L3",
    "semantic": "L4",
}


def run():
    ap = argparse.ArgumentParser(description=__doc__)
    add_model_arg(ap)
    ap.add_argument("--seed", type=int, default=42,
                     help="random seed for the attack batch (default 42, "
                          "matching Run 1 / the confusion matrix chart)")
    ap.add_argument("--attacks", type=int, default=1001,
                     help="number of attacks to generate (default 1001, "
                          "matching thesis_evaluation.py's ATTACK_COUNT)")
    args = ap.parse_args()
    selected_model = resolve_model(args.model)

    print(f"Generating {args.attacks} attacks (seed={args.seed}, same "
          f"method as thesis_evaluation.py)...")
    random.seed(args.seed)
    gen = RealisticAttackGenerator()
    batch = gen.generate_batch(args.attacks, benign_ratio=0.0)
    attacks = [a for a in batch if a.get("is_attack", True)][:args.attacks]
    print(f"  {len(attacks)} attacks generated.")

    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)

    counts = {"L1": 0, "L2": 0, "L3": 0, "L4": 0, "none (reached model)": 0, "other": 0}
    layer_raw_counts = {}
    total = len(attacks)

    for i, atk in enumerate(attacks, 1):
        res = rag.run(atk["payload"])
        layer = res.get("layer", "none")
        layer_raw_counts[layer] = layer_raw_counts.get(layer, 0) + 1

        blocked = res.get("flag") not in ("clean", "baseline", "error")
        if not blocked:
            counts["none (reached model)"] += 1
        elif layer in LAYER_BUCKETS:
            counts[LAYER_BUCKETS[layer]] += 1
        else:
            counts["other"] += 1

        if i % 20 == 0 or i == total:
            print(f"  [{i}/{total}] processing...", end="\r")

    print(f"  [{total}/{total}] done                    \n")

    print("Per-layer blocks (direct measurement, this exact run):")
    for k in ["L1", "L2", "L3", "L4", "none (reached model)", "other"]:
        print(f"  {k:24s} {counts[k]}")
    print(f"\nRaw res['layer'] values seen: {layer_raw_counts}")

    out = {
        "model": selected_model,
        "seed": args.seed,
        "n_attacks": total,
        "layer_counts": counts,
        "raw_layer_values": layer_raw_counts,
        "note": "Direct per-query measurement -- res['layer'] tallied for "
                "every attack in this run, not derived from another chart.",
    }
    out_path = SCRIPT_DIR / f"layer_effectiveness__{safe_filename(selected_model)}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nSaved -> {out_path}")

    # ── cross-check against the ablation-derived figures ──────────────────
    # The ablation study gives the same quantity by a different route:
    # marginal contribution = blocked(config N) - blocked(config N-1). Because
    # blocking is sequential (each query stops at the first layer that catches
    # it), the two methods are mathematically equivalent when both are valid.
    # Printing them side by side turns that equivalence into a check rather
    # than an assumption -- if they disagree, one of the two is wrong and the
    # difference says which layer to look at.
    thesis_path = Path("outputs") / "thesis_v2" / safe_filename(selected_model) / "thesis_results.json"
    derived = None
    if thesis_path.exists():
        t = json.load(open(thesis_path, encoding="utf-8"))
        abl = t.get("ablation_study", {})
        order = ["L0 only", "L0+L1", "L0+L1+L2", "L0+L1+L2+L3"]
        if all(k in abl for k in order):
            runs = t["full_evaluation"]["raw_runs"]
            seed_idx = t["config"]["seeds"].index(args.seed) if args.seed in t["config"]["seeds"] else 0
            b = [abl[k]["blocked"] for k in order] + [runs[seed_idx]["blocked"]]
            derived = [b[i + 1] - b[i] for i in range(4)]
            print("\n" + "=" * 62)
            print("Cross-check: direct measurement vs ablation-derived")
            print("=" * 62)
            print(f"{'layer':8s}{'direct':>10s}{'derived':>10s}{'diff':>8s}")
            print("-" * 62)
            for lab, d in zip(["L1", "L2", "L3", "L4"], derived):
                m = counts[lab]
                print(f"{lab:8s}{m:>10d}{d:>10d}{m - d:>+8d}")
            print(f"{'TOTAL':8s}{sum(counts[k] for k in ('L1','L2','L3','L4')):>10d}"
                  f"{sum(derived):>10d}")
            if all(counts[l] == d for l, d in zip(["L1","L2","L3","L4"], derived)):
                print("\n  The two methods agree exactly.")
            else:
                print("\n  The two methods DIFFER. The direct measurement above is the")
                print("  one to report: it counts which layer actually fired on each")
                print("  query, rather than inferring it from cumulative totals.")
        else:
            print("\n  (no ablation data in thesis_results.json -- cross-check skipped)")
    else:
        print(f"\n  ({thesis_path} not found -- cross-check skipped)")

    # ── chart ─────────────────────────────────────────────────────────────
    labels = ["L1\nSanitization", "L2\nRules", "L3\nAnomaly", "L4\nSemantic"]
    vals = [counts[k] for k in ("L1", "L2", "L3", "L4")]
    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    bars = ax.bar(labels, vals, color=["#5c7a9e", "#5c7a9e", "#93a8bd", "#93a8bd"])
    for b_, v in zip(bars, vals):
        ax.text(b_.get_x() + b_.get_width() / 2, v + max(vals) * 0.02, str(v),
                ha="center", fontweight="bold", fontsize=13)
    ax.set_ylabel("attacks blocked")
    ax.set_title(f"Defense Layer Effectiveness — {selected_model}\n"
                 f"direct per-query measurement, seed={args.seed}, n={total} attacks",
                 fontweight="bold", fontsize=12)
    blocked_total = sum(vals)
    ax.text(0.99, 0.97, f"blocked {blocked_total}/{total} = {100*blocked_total/total:.2f}%\n"
                        f"reached model {counts['none (reached model)']}",
            transform=ax.transAxes, ha="right", va="top", fontsize=9,
            bbox=dict(boxstyle="round,pad=0.4", fc="#f0f0f0", ec="#cccccc"))
    plt.tight_layout()
    out_dir = Path("final_charts") / safe_filename(selected_model)
    os.makedirs(out_dir, exist_ok=True)
    png = out_dir / "05_layer_effectiveness.png"
    fig.savefig(png, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\nChart -> {png}")
    print("(this overwrites the ablation-derived version of chart 05; "
          "generate_final_charts.py will also pick the JSON up automatically)")


if __name__ == "__main__":
    run()
