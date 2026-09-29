#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase4_analysis.py  --  examiner items A-9 (ROC/PR), A-8 (kappa), A-10
==============================================================================
Runs entirely on files already produced. No model, no generation.

A-9  ROC and precision-recall for L4, built from the similarity scores every
     run already logs (attack responses that reached L4 vs benign responses
     that reached L4). The thesis picks 0.18 from a two-sided sweep but never
     shows the curve the examiner asked for.
A-8  Accuracy and Cohen's kappa for the compliance classifier, from the
     manual labelling sheet once human_verdict is filled in.
A-10 Wilson interval on POOLED counts, which is what the examiner asked for
     in place of McNemar (whose c = 0 is true by construction).

Usage:  python3 changeb4/phase4_analysis.py
"""
import csv
import glob
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import OUT_ROOT, save_json, out_dir  # noqa: E402


def wilson(x, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = x / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z / d * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(100 * (c - h), 2), round(100 * (c + h), 2))


def read_csv(p):
    try:
        return list(csv.DictReader(open(p, encoding="utf-8")))
    except Exception:
        return []


def fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ── A-9 ────────────────────────────────────────────────────────────────────
def l4_curves():
    """Pools every logged L4 similarity score: attacks that reached L4
    (positives -- L4 should block) against benign that reached L4
    (negatives -- L4 should pass)."""
    pos, neg = [], []
    for p in glob.glob(str(ROOT / "bipia_external_results*.csv")) + \
             glob.glob(str(OUT_ROOT / "**" / "*results*.csv"), recursive=True):
        for r in read_csv(p):
            s = fnum(r.get("similarity_score"))
            if s is not None:
                pos.append(s)
    for p in glob.glob(str(ROOT / "bipia_external_fpr_results*.csv")) + \
             glob.glob(str(OUT_ROOT / "**" / "*real_query_full_pipeline*.csv"),
                       recursive=True):
        for r in read_csv(p):
            s = fnum(r.get("similarity_score"))
            if s is not None:
                neg.append(s)
    if not pos or not neg:
        return {"available": False,
                "note": "needs at least one attack-side and one benign-side "
                        "results CSV carrying similarity_score"}

    pts = []
    thresholds = [round(t, 3) for t in
                  [i / 200 for i in range(0, 201)]]
    for t in thresholds:
        tp = sum(1 for s in pos if s < t)     # L4 blocks when sim < threshold
        fn = len(pos) - tp
        fp = sum(1 for s in neg if s < t)
        tn = len(neg) - fp
        tpr = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        prec = tp / max(tp + fp, 1)
        pts.append({"threshold": t, "tpr_recall": round(tpr, 4),
                    "fpr": round(fpr, 4), "precision": round(prec, 4)})
    pts_sorted = sorted(pts, key=lambda d: d["fpr"])
    auc = 0.0
    for a, b in zip(pts_sorted, pts_sorted[1:]):
        auc += (b["fpr"] - a["fpr"]) * (a["tpr_recall"] + b["tpr_recall"]) / 2
    at18 = min(pts, key=lambda d: abs(d["threshold"] - 0.18))
    return {"available": True, "n_positive": len(pos), "n_negative": len(neg),
            "auc": round(auc, 4), "operating_point_0_18": at18, "curve": pts}


# ── A-8 ────────────────────────────────────────────────────────────────────
def kappa():
    p = OUT_ROOT / "phase2" / "A8_manual_labelling_sheet.csv"
    rows = [r for r in read_csv(p) if (r.get("human_verdict") or "").strip()]
    if not rows:
        return {"available": False,
                "note": f"fill human_verdict in {p.name} (complied / resisted)"}
    def norm(v):
        v = v.strip().lower()
        return "complied" if v.startswith("c") else "resisted"
    auto = [("complied" if r["auto_verdict"] == "possibly_complied" else "resisted")
            for r in rows]
    human = [norm(r["human_verdict"]) for r in rows]
    n = len(rows)
    agree = sum(1 for a, h in zip(auto, human) if a == h)
    po = agree / n
    pe = sum((auto.count(c) / n) * (human.count(c) / n)
             for c in ("complied", "resisted"))
    k = (po - pe) / (1 - pe) if pe < 1 else 1.0
    tp = sum(1 for a, h in zip(auto, human) if a == h == "complied")
    fp = sum(1 for a, h in zip(auto, human) if a == "complied" and h == "resisted")
    fn = sum(1 for a, h in zip(auto, human) if a == "resisted" and h == "complied")
    return {"available": True, "n_labelled": n,
            "accuracy_pct": round(100 * po, 2),
            "cohens_kappa": round(k, 3),
            "precision": round(tp / max(tp + fp, 1), 3),
            "recall": round(tp / max(tp + fn, 1), 3)}


# ── A-10 ───────────────────────────────────────────────────────────────────
def pooled_intervals():
    p = OUT_ROOT / "phase0" / "phase0_results.json"
    out = {"note": "Wilson on pooled counts, the examiner's replacement for "
                   "McNemar (c = 0 by construction)."}
    import json
    if p.exists():
        d = json.load(open(p, encoding="utf-8"))
        for mode in ("delete", "space"):
            if mode not in d:
                continue
            runs = d[mode]["A3_tuning"]["runs"]
            n = sum(r["n_attacks"] for r in runs)
            reached = sum(r["n_attacks"] - r["blocked"] for r in runs)
            fpn = sum(r["n_benign"] for r in runs)
            fp = sum(r["fp_pre_l4"] for r in runs)
            out[f"zwsp_{mode}"] = {
                "pooled_asr_pre_l4": {"x": reached, "n": n,
                                      "pct": round(100 * reached / n, 2),
                                      "wilson95": wilson(reached, n)},
                "pooled_fpr_pre_l4": {"x": fp, "n": fpn,
                                      "pct": round(100 * fp / fpn, 3),
                                      "wilson95": wilson(fp, fpn)},
            }
    out["thesis_reference"] = {
        "asr_full_pipeline_pooled_example": {"x": 489, "n": 5005,
                                             "wilson95": wilson(489, 5005)},
    }
    return out


def main():
    print("=" * 74)
    print("Change-B4 / Phase 4 -- analysis of files already produced")
    print("=" * 74)
    res = {"A9_l4_roc_pr": l4_curves(),
           "A8_classifier_validation": kappa(),
           "A10_pooled_wilson": pooled_intervals()}

    r9 = res["A9_l4_roc_pr"]
    if r9.get("available"):
        print(f"  A-9  L4 ROC: n+={r9['n_positive']} n-={r9['n_negative']}  "
              f"AUC={r9['auc']}")
        op = r9["operating_point_0_18"]
        print(f"       at 0.18: recall={op['tpr_recall']}  fpr={op['fpr']}  "
              f"precision={op['precision']}")
    else:
        print(f"  A-9  {r9['note']}")

    r8 = res["A8_classifier_validation"]
    print(f"  A-8  {'kappa=' + str(r8['cohens_kappa']) + '  acc=' + str(r8['accuracy_pct']) + '%' if r8.get('available') else r8['note']}")

    for k, v in res["A10_pooled_wilson"].items():
        if k.startswith("zwsp_"):
            a = v["pooled_asr_pre_l4"]
            print(f"  A-10 {k}: pooled ASR(pre-L4) {a['pct']}%  "
                  f"Wilson95 {a['wilson95']}")

    save_json(res, "phase4", "phase4_analysis.json")
    print("\nPhase 4 complete.")


if __name__ == "__main__":
    main()
