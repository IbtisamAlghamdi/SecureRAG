#!/usr/bin/env python3
"""Obfuscation-variant detection and L2 pattern-tier attribution.

Two numbers the main evaluation does not record are still outstanding: the
detection rate of each obfuscation variant, and the split of L2's blocks
across the five pattern tiers that share a single log key.

Both are properties of the input layers alone. No model is loaded and no
retrieval happens, so this reproduces the decisions of the live run from
the generators in seconds rather than hours.

The script refuses to report anything until it has reproduced the live
run's own layer counts. If those do not match, the configuration differs
from the one that produced the reported results and the output would be
describing a different system.

    python3 changeb4/phase14_variants_and_tiers.py
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from changeb4.common import (  # noqa: E402
    make_batch, base_tier, run_input_layers, save_csv, save_json,
)

SEEDS = [839, 941, 1049, 1151, 1279]
N_ATTACKS = 1001
N_BENIGN = 333

# What the live five-seed run recorded. Anything else means a different
# configuration is in effect and the new figures would not be comparable.
EXPECTED = {"L1": 826, "L2": 3523, "L3": 123}

VARIANTS = ("base64", "zwsp", "homoglyph", "context_wrap")


def split_type(t: str):
    """'semantic_camouflage_base64' -> ('semantic_camouflage', 'base64').

    base_tier matches on substrings and ignores the suffix, so the category
    is read from the whole string and only the variant needs stripping.
    """
    t = (t or "").lower()
    for v in VARIANTS:
        if t.endswith("_" + v):
            return base_tier(t), v
    return base_tier(t), "plain"


def main() -> int:
    by_layer = Counter()
    by_tier = Counter()
    variant = defaultdict(lambda: {"n": 0, "blocked": 0, "by_layer": Counter()})
    cat_variant = defaultdict(lambda: {"n": 0, "blocked": 0})
    rows = []

    for seed in SEEDS:
        attacks, _benign = make_batch(seed, N_ATTACKS, N_BENIGN)
        if len(attacks) != N_ATTACKS:
            print(f"  seed {seed}: expected {N_ATTACKS} attacks, got {len(attacks)}")
            return 2

        for a in attacks:
            cat, var = split_type(a["type"])
            res = run_input_layers(a["query"])
            layer = res.get("blocked_at")
            blocked = layer is not None

            if blocked:
                by_layer[layer] += 1
                if layer == "L2":
                    by_tier[res.get("violation_type") or "unlabelled"] += 1

            variant[var]["n"] += 1
            variant[var]["blocked"] += blocked
            if blocked:
                variant[var]["by_layer"][layer] += 1

            key = (cat, var)
            cat_variant[key]["n"] += 1
            cat_variant[key]["blocked"] += blocked

            rows.append({
                "seed": seed, "category": cat, "variant": var,
                "blocked": blocked, "layer": layer or "none",
                "violation_type": res.get("violation_type") or "",
                "risk": res.get("risk", ""),
                "anomaly_score": res.get("anomaly_score", ""),
                "l4_gate_open": res.get("l4_gate_open", ""),
            })

    # --- parity gate -------------------------------------------------
    got = {k: by_layer.get(k, 0) for k in EXPECTED}
    print("\nparity against the live five-seed run")
    ok = True
    for k, want in EXPECTED.items():
        mark = "ok" if got[k] == want else "MISMATCH"
        if got[k] != want:
            ok = False
        print(f"  {k}: {got[k]:>5}  expected {want:>5}   {mark}")
    if not ok:
        print("\n  Layer counts differ from the run that produced the reported")
        print("  results. Check SECURERAG_B64_RULE_MODE=decode and")
        print("  SECURERAG_ZWSP_MODE=space, then run again. Nothing was saved.")
        return 1
    print("  reproduced exactly; the figures below describe the same system\n")

    total = sum(v["n"] for v in variant.values())

    # --- obfuscation variants ---------------------------------------
    print("detection by obfuscation variant (input layers only)")
    print(f"  {'variant':<14}{'n':>6}{'detected':>10}{'rate':>9}   layers")
    var_out = {}
    for var in ("plain",) + VARIANTS:
        v = variant.get(var)
        if not v or not v["n"]:
            continue
        rate = 100.0 * v["blocked"] / v["n"]
        layers = " ".join(f"{k}={c}" for k, c in sorted(v["by_layer"].items()))
        print(f"  {var:<14}{v['n']:>6}{v['blocked']:>10}{rate:>8.2f}%   {layers}")
        var_out[var] = {"n": v["n"], "detected": v["blocked"],
                        "detection_pct": round(rate, 2),
                        "by_layer": dict(v["by_layer"])}

    # --- the same, for semantic camouflage alone ---------------------
    print("\nsemantic camouflage by variant (input layers only)")
    sc = {}
    for (cat, var), v in sorted(cat_variant.items()):
        if cat != "semantic_camouflage" or not v["n"]:
            continue
        rate = 100.0 * v["blocked"] / v["n"]
        print(f"  {var:<14}{v['n']:>6}{v['blocked']:>10}{rate:>8.2f}%")
        sc[var] = {"n": v["n"], "detected": v["blocked"],
                   "detection_pct": round(rate, 2)}

    # --- L2 pattern tiers -------------------------------------------
    print("\nL2 blocks by pattern tier")
    tier_out = {}
    for tier, c in by_tier.most_common():
        print(f"  {tier:<28}{c:>6}{100.0 * c / by_layer['L2']:>8.2f}% of L2")
        tier_out[tier] = c

    save_csv(rows, "phase14", "A29_variant_tier_rows.csv")
    save_json({
        "seeds": SEEDS,
        "n_attacks_pooled": total,
        "parity": {"expected": EXPECTED, "observed": got, "matched": True},
        "blocks_by_layer": dict(by_layer),
        "by_variant": var_out,
        "semantic_camouflage_by_variant": sc,
        "l2_by_tier": tier_out,
        "reading": (
            "Detection here is by the input layers only. The output guardrail "
            "sees a generated answer, which this script does not produce, so "
            "its contribution is not included and the complete-system figures "
            "in phase5 are correspondingly higher."
        ),
    }, "phase14", "A29_variant_tier_summary.json")
    print("\ndone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
