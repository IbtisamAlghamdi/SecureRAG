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

BUCKETING FIX (this is what the first version of this script got wrong):
pipeline.py does NOT emit a single flat "rules" label. Line 204 builds
    block_key = f"rules_{violation_type}" if f"rules_{violation_type}"
                in BLOCK_MESSAGES else "rules"
so res['layer'] can be any of rules, rules_direct_injection,
rules_prompt_extraction, rules_role_redefinition, rules_indirect_attack,
rules_data_exfiltration -- and likewise template_injection for L1. A
hard-coded exact-match dict missed every rules_* variant and silently
swept them into an "other" bucket, under-reporting L2 by 488 blocks on
the Mistral-7B run and producing a fake disagreement with the ablation
cross-check. The fix is to stop hand-maintaining a list and instead use
the EXACT same collapsing rule pipeline._block() itself uses:
    layer_base = layer.split("_")[0] if "_" in layer else layer
Any future rules_<newtype> is then bucketed correctly by construction,
and an unrecognised base raises instead of being quietly discarded.

Usage:
    conda activate RAG

    # (a) full measurement -- loads the model, ~the same cost as one Run
    python3 measure_layer_effectiveness.py --model Mistral-7B

    # (b) re-bucket + redraw from a JSON this script already produced,
    #     with NO model load and no re-run (seconds, not hours):
    python3 measure_layer_effectiveness.py --from-json layer_effectiveness__Mistral7B.json

Output:
    layer_effectiveness__<model>.json  -- read directly by
    generate_final_charts.py's chart_layer_effectiveness() (it prefers
    this real file over the derived-delta fallback when present).
    final_charts/<model>/05_layer_effectiveness.png
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from model_select import add_model_arg, resolve_model, safe_filename

SCRIPT_DIR = Path(__file__).parent

# Maps the COLLAPSED base of pipeline.py's res['layer'] to the 4 defense
# layers this chart reports. The collapsing is done by layer_base() below
# using pipeline._block()'s own rule, so every rules_* variant lands here
# as plain "rules" and every template_injection lands as "template".
#
#   res['layer'] value            -> base            -> bucket
#   "template_injection"             "template"         L1
#   "sanitization"                   "sanitization"     L1
#   "rules"                          "rules"            L2
#   "rules_direct_injection"         "rules"            L2
#   "rules_prompt_extraction"        "rules"            L2
#   "rules_role_redefinition"        "rules"            L2
#   "rules_indirect_attack"          "rules"            L2
#   "rules_data_exfiltration"        "rules"            L2
#   "anomaly"                        "anomaly"          L3
#   "semantic"                       "semantic"         L4
BASE_TO_LAYER = {
    "template":     "L1",
    "sanitization": "L1",
    "rules":        "L2",
    "anomaly":      "L3",
    "semantic":     "L4",
}

# res['layer'] values that mean "not blocked by L1-L4".
NOT_A_BLOCK = {"none", "error", "clean", "baseline"}

BUCKET_KEYS = ("L1", "L2", "L3", "L4")
REACHED_KEY = "none (reached model)"


def layer_base(layer: str) -> str:
    """EXACTLY pipeline._block()'s collapsing rule -- kept identical on
    purpose so this script cannot drift from what the pipeline emits."""
    return layer.split("_")[0] if "_" in layer else layer


def bucket_counts(raw_layer_values: dict) -> dict:
    """Single source of truth for turning raw res['layer'] tallies into the
    4 reported buckets. Both the live run and --from-json go through this
    function, so the chart and the JSON can never disagree.

    Raises on any layer value it does not recognise -- an unmapped block
    must fail loudly, not vanish into an 'other' bucket. That silent
    'other' bucket is precisely what produced the wrong L2=232 figure."""
    counts = {k: 0 for k in BUCKET_KEYS}
    counts[REACHED_KEY] = 0
    unknown = {}

    for layer, n in raw_layer_values.items():
        if layer in NOT_A_BLOCK:
            counts[REACHED_KEY] += n
            continue
        base = layer_base(layer)
        if base in BASE_TO_LAYER:
            counts[BASE_TO_LAYER[base]] += n
        else:
            unknown[layer] = n

    if unknown:
        raise SystemExit(
            f"\nFATAL: unmapped res['layer'] value(s): {unknown}\n"
            f"  Every block MUST map to L1-L4. Add the base "
            f"'{', '.join(sorted({layer_base(k) for k in unknown}))}' to "
            f"BASE_TO_LAYER in this file (or to NOT_A_BLOCK if it is not a "
            f"block). Refusing to draw a chart with missing blocks."
        )
    return counts


def rules_breakdown(raw_layer_values: dict) -> list:
    """Which rule types make up L2 -- reported because 'L2 blocked 720' on
    its own hides that it is four distinct violation types."""
    rows = [(k, v) for k, v in raw_layer_values.items() if layer_base(k) == "rules"]
    return sorted(rows, key=lambda kv: -kv[1])


def report(counts, raw, total):
    print("Per-layer blocks (direct measurement, this exact run):")
    for k in list(BUCKET_KEYS) + [REACHED_KEY]:
        print(f"  {k:24s} {counts[k]}")
    blocked = sum(counts[k] for k in BUCKET_KEYS)
    print(f"  {'-'*24} ----")
    print(f"  {'blocked (L1-L4)':24s} {blocked}")
    print(f"  {'TOTAL':24s} {blocked + counts[REACHED_KEY]}  (must equal {total})")

    if blocked + counts[REACHED_KEY] != total:
        raise SystemExit(
            f"\nFATAL: blocked ({blocked}) + reached ({counts[REACHED_KEY]}) "
            f"!= total ({total}). Queries have gone missing -- not drawing a chart."
        )

    print(f"\nRaw res['layer'] values seen: {raw}")

    br = rules_breakdown(raw)
    if br:
        l2 = counts["L2"]
        print(f"\nL2 breakdown (the {l2} rule blocks, by violation type):")
        for k, v in br:
            print(f"  {k:28s} {v:5d}  ({100*v/l2:5.1f}% of L2)")


def cross_check(counts, selected_model, seed):
    """The ablation study gives the same quantity by a different route:
    marginal contribution = blocked(config N) - blocked(config N-1). Because
    blocking is sequential (each query stops at the first layer that catches
    it), the two methods are mathematically equivalent when both are valid.
    Printing them side by side turns that equivalence into a check rather
    than an assumption."""
    thesis_path = Path("outputs") / "thesis_v2" / safe_filename(selected_model) / "thesis_results.json"
    if not thesis_path.exists():
        print(f"\n  ({thesis_path} not found -- cross-check skipped)")
        return
    t = json.load(open(thesis_path, encoding="utf-8"))
    abl = t.get("ablation_study", {})
    order = ["L0 only", "L0+L1", "L0+L1+L2", "L0+L1+L2+L3"]
    if not all(k in abl for k in order):
        print("\n  (no ablation data in thesis_results.json -- cross-check skipped)")
        return

    runs = t["full_evaluation"]["raw_runs"]
    seeds = t["config"]["seeds"]
    seed_idx = seeds.index(seed) if seed in seeds else 0
    b = [abl[k]["blocked"] for k in order] + [runs[seed_idx]["blocked"]]
    derived = [b[i + 1] - b[i] for i in range(4)]

    print("\n" + "=" * 62)
    print("Cross-check: direct measurement vs ablation-derived")
    print("=" * 62)
    print(f"{'layer':8s}{'direct':>10s}{'derived':>10s}{'diff':>8s}")
    print("-" * 62)
    for lab, d in zip(BUCKET_KEYS, derived):
        print(f"{lab:8s}{counts[lab]:>10d}{d:>10d}{counts[lab] - d:>+8d}")
    print(f"{'TOTAL':8s}{sum(counts[k] for k in BUCKET_KEYS):>10d}{sum(derived):>10d}")
    if all(counts[l] == d for l, d in zip(BUCKET_KEYS, derived)):
        print("\n  The two methods agree exactly.")
    else:
        print("\n  The two methods DIFFER. The direct measurement above is the")
        print("  one to report: it counts which layer actually fired on each")
        print("  query, rather than inferring it from cumulative totals.")


def draw(counts, selected_model, seed, total, raw):
    labels = ["L1\nSanitization", "L2\nRules", "L3\nAnomaly", "L4\nSemantic"]
    vals = [counts[k] for k in BUCKET_KEYS]
    blocked_total = sum(vals)

    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    bars = ax.bar(labels, vals, color=["#5c7a9e", "#5c7a9e", "#93a8bd", "#93a8bd"])
    for b_, v in zip(bars, vals):
        pct = 100 * v / blocked_total if blocked_total else 0
        ax.text(b_.get_x() + b_.get_width() / 2, v + max(vals) * 0.02,
                f"{v}\n{pct:.1f}%", ha="center", fontweight="bold", fontsize=12)
    ax.set_ylim(0, max(vals) * 1.20)
    ax.set_ylabel("attacks blocked")
    ax.set_title(f"Defense Layer Effectiveness — {selected_model}\n"
                 f"direct per-query measurement, seed={seed}, n={total} attacks",
                 fontweight="bold", fontsize=12)
    ax.text(0.99, 0.97,
            f"blocked {blocked_total}/{total} = {100*blocked_total/total:.2f}%\n"
            f"reached model {counts[REACHED_KEY]}",
            transform=ax.transAxes, ha="right", va="top", fontsize=9,
            bbox=dict(boxstyle="round,pad=0.4", fc="#f0f0f0", ec="#cccccc"))

    br = rules_breakdown(raw)
    if br:
        note = "L2 = " + ", ".join(f"{k.replace('rules_', '') if k != 'rules' else 'generic'} {v}"
                                    for k, v in br)
        ax.text(0.5, -0.13, note, transform=ax.transAxes, ha="center",
                va="top", fontsize=8, color="#555555")

    plt.tight_layout()
    out_dir = Path("final_charts") / safe_filename(selected_model)
    os.makedirs(out_dir, exist_ok=True)
    png = out_dir / "05_layer_effectiveness.png"
    fig.savefig(png, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\nChart -> {png}")


def save_json(counts, raw, selected_model, seed, total, out_path=None):
    out = {
        "model": selected_model,
        "seed": seed,
        "n_attacks": total,
        "layer_counts": counts,
        "raw_layer_values": raw,
        "l2_breakdown": dict(rules_breakdown(raw)),
        "note": "Direct per-query measurement -- res['layer'] tallied for "
                "every attack in this run, not derived from another chart. "
                "Bucketed via pipeline._block()'s own layer.split('_')[0] "
                "rule, so all rules_* variants count as L2.",
    }
    # In --from-json mode the caller passes the file it read, so the
    # corrected counts overwrite that same file rather than creating a
    # second JSON under a re-derived name.
    if out_path is None:
        out_path = SCRIPT_DIR / f"layer_effectiveness__{safe_filename(selected_model)}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nSaved -> {out_path}")


def from_json(path):
    """Re-bucket and redraw from a JSON this script already wrote. No model
    load, no re-run -- the raw per-query res['layer'] tallies are already
    stored, so a bucketing bug is fixable without repeating the run."""
    d = json.load(open(path, encoding="utf-8"))
    raw = d.get("raw_layer_values")
    if not raw:
        raise SystemExit(f"{path} has no 'raw_layer_values' -- cannot re-bucket. "
                         f"Re-run the full measurement instead.")
    selected_model = d["model"]
    seed = d.get("seed", 42)
    total = d.get("n_attacks") or sum(raw.values())

    print(f"Re-bucketing from {path} (no model load, no re-run)")
    print(f"  model={selected_model}  seed={seed}  n={total}\n")

    counts = bucket_counts(raw)
    report(counts, raw, total)
    save_json(counts, raw, selected_model, seed, total, out_path=Path(path))
    cross_check(counts, selected_model, seed)
    draw(counts, selected_model, seed, total, raw)


def live_run(args):
    from src.config import settings
    from src.pipeline import SecureRAG, BLOCK_MESSAGES
    from src.attacks.generator import RealisticAttackGenerator

    # Guard: assert every label pipeline.py can possibly emit is bucketable
    # BEFORE spending hours on a run, rather than discovering it at the end.
    bad = [k for k in BLOCK_MESSAGES if layer_base(k) not in BASE_TO_LAYER]
    if bad:
        raise SystemExit(f"FATAL: pipeline.BLOCK_MESSAGES contains labels this "
                         f"script cannot bucket: {bad}. Update BASE_TO_LAYER.")
    print(f"Bucketing self-check: all {len(BLOCK_MESSAGES)} pipeline block "
          f"labels map to L1-L4. OK\n")

    print(f"Generating {args.attacks} attacks (seed={args.seed}, same "
          f"method as thesis_evaluation.py)...")
    random.seed(args.seed)
    gen = RealisticAttackGenerator()
    batch = gen.generate_batch(args.attacks, benign_ratio=0.0)
    attacks = [a for a in batch if a.get("is_attack", True)][:args.attacks]
    print(f"  {len(attacks)} attacks generated.")

    selected_model = resolve_model(args.model)
    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)

    raw = {}
    total = len(attacks)
    for i, atk in enumerate(attacks, 1):
        res = rag.run(atk["payload"])
        layer = res.get("layer", "none")
        # A non-block must be recorded as such even if 'layer' says otherwise.
        if res.get("flag") in ("clean", "baseline", "error"):
            layer = "none"
        raw[layer] = raw.get(layer, 0) + 1
        if i % 20 == 0 or i == total:
            print(f"  [{i}/{total}] processing...", end="\r")
    print(f"  [{total}/{total}] done                    \n")

    counts = bucket_counts(raw)
    report(counts, raw, total)
    save_json(counts, raw, selected_model, args.seed, total)
    cross_check(counts, selected_model, args.seed)
    draw(counts, selected_model, args.seed, total, raw)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_model_arg(ap)
    ap.add_argument("--seed", type=int, default=42,
                    help="random seed for the attack batch (default 42, "
                         "matching Run 1 / the confusion matrix chart)")
    ap.add_argument("--attacks", type=int, default=1001,
                    help="number of attacks to generate (default 1001, "
                         "matching thesis_evaluation.py's ATTACK_COUNT)")
    ap.add_argument("--from-json", default=None, metavar="PATH",
                    help="skip the run entirely: re-bucket and redraw from an "
                         "existing layer_effectiveness__<model>.json using its "
                         "stored raw_layer_values")
    args = ap.parse_args()

    if args.from_json:
        from_json(args.from_json)
    else:
        live_run(args)


if __name__ == "__main__":
    main()
