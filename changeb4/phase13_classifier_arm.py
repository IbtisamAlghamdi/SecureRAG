#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase13_classifier_arm.py  --  item A-14 (classifier arm)
==================================================================
The review asked for at least two reference defenses on the same data, and
named an open-source classifier -- Prompt Guard or Llama Guard -- as one of
them. Sandwich and Spotlighting are already done in phase6; this adds the
classifier.

Meta's Prompt Guard sits behind a gated licence on the Hub. The script tries
it first when a token is present and otherwise falls back to an ungated model
of the same kind. Whichever loads is recorded in the output, because the
identity of the reference defense is part of the result.

The comparison is paired: every query is judged by both the classifier and
SecureRAG's input layers, on the same batches, so McNemar applies to the
discordant pairs rather than to two separate runs.

No language model is loaded -- this compares detectors, not generations.

Usage:
  python3 changeb4/phase13_classifier_arm.py --seeds 839 941 1049 1151 1279
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changeb4.common import make_batch, base_tier, save_csv, save_json  # noqa

CANDIDATES = [
    ("meta-llama/Prompt-Guard-86M", "gated"),
    ("protectai/deberta-v3-base-prompt-injection-v2", "open"),
    ("protectai/deberta-v3-base-prompt-injection", "open"),
]


def mcnemar(b, c):
    if b + c == 0:
        return {"b": b, "c": c, "chi2": 0.0, "p_lt_0_05": False, "p_lt_0_001": False}
    chi2 = (abs(b - c) - 1) ** 2 / (b + c) if abs(b - c) > 1 else 0.0
    return {"b": b, "c": c, "chi2": round(chi2, 2),
            "p_lt_0_05": chi2 > 3.841, "p_lt_0_001": chi2 > 10.828}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="*",
                    default=[839, 941, 1049, 1151, 1279])
    ap.add_argument("--model", default=None, help="override the classifier id")
    args = ap.parse_args()

    from transformers import pipeline
    from changeb4.common import run_input_layers

    clf = name = None
    for mid, kind in ([(args.model, "explicit")] if args.model else CANDIDATES):
        try:
            print(f"  trying {mid} ...", flush=True)
            clf = pipeline("text-classification", model=mid, truncation=True, max_length=512)
            name = mid
            print(f"  loaded {mid} ({kind})")
            break
        except Exception as e:
            print(f"    unavailable: {str(e)[:110]}")
    if clf is None:
        print("ERROR: no classifier could be loaded. Set HF_TOKEN for the gated "
              "model, or pass --model with one you have.")
        return 1

    def flags_attack(text):
        out = clf(text[:4000])[0]
        lab = str(out.get("label", "")).upper()
        return lab in ("INJECTION", "JAILBREAK", "MALICIOUS", "LABEL_1", "UNSAFE")

    rows = []
    tot = {"a": 0, "clf_a": 0, "sr_a": 0, "b": 0, "clf_b": 0, "sr_b": 0}
    disc_b = disc_c = 0
    by_cat = {}

    for seed in args.seeds:
        attacks, benign = make_batch(seed)
        print(f"\n--- seed {seed}: {len(attacks)} attacks + {len(benign)} benign", flush=True)
        for i, a in enumerate(attacks, 1):
            q = a["payload"]
            c_hit = flags_attack(q)
            s_hit = run_input_layers(q)["blocked_at"] is not None
            cat = base_tier(a["type"])
            d = by_cat.setdefault(cat, {"n": 0, "clf": 0, "sr": 0})
            d["n"] += 1; d["clf"] += c_hit; d["sr"] += s_hit
            tot["a"] += 1; tot["clf_a"] += c_hit; tot["sr_a"] += s_hit
            if s_hit and not c_hit: disc_b += 1
            if c_hit and not s_hit: disc_c += 1
            rows.append({"seed": seed, "kind": "attack", "category": cat,
                         "classifier_blocked": c_hit, "securerag_blocked": s_hit})
            if i % 200 == 0:
                print(f"    {i}/{len(attacks)}", flush=True)
        for q in benign:
            c_hit = flags_attack(q)
            s_hit = run_input_layers(q)["blocked_at"] is not None
            tot["b"] += 1; tot["clf_b"] += c_hit; tot["sr_b"] += s_hit
            rows.append({"seed": seed, "kind": "benign", "category": "benign",
                         "classifier_blocked": c_hit, "securerag_blocked": s_hit})

    res = {
        "classifier": name,
        "seeds": args.seeds,
        "n_attacks": tot["a"], "n_benign": tot["b"],
        "classifier_detection_pct": round(100 * tot["clf_a"] / max(tot["a"], 1), 2),
        "securerag_detection_pct": round(100 * tot["sr_a"] / max(tot["a"], 1), 2),
        "classifier_fpr_pct": round(100 * tot["clf_b"] / max(tot["b"], 1), 2),
        "securerag_fpr_pct": round(100 * tot["sr_b"] / max(tot["b"], 1), 2),
        "mcnemar_securerag_vs_classifier": mcnemar(disc_b, disc_c),
        "detection_by_category_pct": {
            c: {"classifier": round(100 * d["clf"] / d["n"], 2),
                "securerag": round(100 * d["sr"] / d["n"], 2)}
            for c, d in sorted(by_cat.items())},
        "note": ("SecureRAG's side is its input layers only (L0-L3), which is the "
                 "like-for-like comparison: the classifier also judges the query "
                 "text alone and never sees a generated answer."),
    }
    print("\n" + "=" * 74)
    print(f"  classifier              {name}")
    print(f"  detection   classifier {res['classifier_detection_pct']:6.2f}%   "
          f"SecureRAG {res['securerag_detection_pct']:6.2f}%")
    print(f"  FPR         classifier {res['classifier_fpr_pct']:6.2f}%   "
          f"SecureRAG {res['securerag_fpr_pct']:6.2f}%")
    print(f"  McNemar     {res['mcnemar_securerag_vs_classifier']}")
    save_csv(rows, "phase13", "A14_classifier_arm_rows.csv")
    save_json(res, "phase13", "A14_classifier_arm_summary.json")
    print("\n  saved -> Change-B4/phase13/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
