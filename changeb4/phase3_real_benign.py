#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase3_real_benign.py  --  examiner items A-20, A-6
============================================================
A-20 The benign set is template-generated and 315/333 score zero, so it is
     easy. The examiner asks for real queries (BEIR NQ / SciFact / FiQA are
     already downloaded by download_datasets.py) and for the fourth FPR
     measurement, which the appendix mentions but the thesis never reports.
A-6  The 61.3% latency reduction is dominated by the 75% of the test set that
     is attacks blocked early. The examiner asks for latency on LEGITIMATE
     queries only, defended versus undefended, i.e. the overhead a real user
     actually pays.

Note on check_real_query_fpr.py: its local ars_prescreen() compares the
BOOLEAN returned by quick_high_risk_scan() against a numeric threshold, so it
can never return HIGH and its L0 does not match src/pipeline.py. This phase
uses changeb4/common.run_input_layers instead, which mirrors the pipeline
exactly (and is verified against it by verify_parity).

Usage:
  python3 changeb4/phase3_real_benign.py --model Mistral-7B --n-full 150
"""
import argparse
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import run_input_layers, save_csv, save_json  # noqa: E402

FILES = ["beir_nq_queries.txt", "beir_scifact_queries.txt", "beir_fiqa_queries.txt"]


def load_real_queries():
    out = {}
    for name in FILES:
        p = ROOT / "data" / name
        if p.exists():
            qs = [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
            out[name] = qs
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Mistral-7B")
    ap.add_argument("--n-full", type=int, default=150,
                    help="how many real queries to run through the COMPLETE "
                         "pipeline (adds L4 and latency; needs the model)")
    ap.add_argument("--skip-model", action="store_true",
                    help="pre-L4 measurement only")
    args = ap.parse_args()

    sets = load_real_queries()
    if not sets:
        raise SystemExit("no data/beir_*_queries.txt found -- run "
                         "download_datasets.py first")

    # ── pre-L4 on everything (free) ────────────────────────────────────────
    rows, per_source = [], {}
    for name, qs in sets.items():
        blocked = 0
        for q in qs:
            r = run_input_layers(q)
            if r["blocked_at"]:
                blocked += 1
                rows.append({"source": name, "query": q,
                             "blocked_at": r["blocked_at"], "flag": r["flag"],
                             "violation_type": r["violation_type"] or "",
                             "anomaly_score": r["anomaly_score"]})
        per_source[name] = {"n": len(qs), "blocked_pre_l4": blocked,
                            "fpr_pre_l4_pct": round(100 * blocked / len(qs), 3)}
        print(f"  {name:<28} {blocked}/{len(qs)} blocked pre-L4 "
              f"({per_source[name]['fpr_pre_l4_pct']}%)")
    save_csv(rows, "phase3", "A20_real_query_pre_l4_blocks.csv")

    total_n = sum(v["n"] for v in per_source.values())
    total_b = sum(v["blocked_pre_l4"] for v in per_source.values())
    result = {"item": "A-20 / A-6", "pre_l4": {
        "per_source": per_source, "total_n": total_n, "total_blocked": total_b,
        "fpr_pre_l4_pct": round(100 * total_b / total_n, 3)}}

    if not args.skip_model:
        from src.config import settings
        from model_select import resolve_model
        resolve_model(args.model)
        from src.pipeline import SecureRAG

        pool = [q for qs in sets.values() for q in qs]
        random.seed(42)
        sample = random.sample(pool, min(args.n_full, len(pool)))
        print(f"\nrunning {len(sample)} real queries through the complete pipeline")

        full_rows = []
        for tag, defended in (("securerag", True), ("baseline", False)):
            rag = SecureRAG(enable_defenses=defended,
                            model_path=settings.LLM_MODEL_PATH)
            t0 = time.time()
            for i, q in enumerate(sample, 1):
                res = rag.run(q)
                blk = res.get("flag") not in ("clean", "baseline", "error")
                full_rows.append({
                    "run": tag, "query": q, "blocked": blk,
                    "flag": res.get("flag", ""), "layer": res.get("layer", ""),
                    "risk": res.get("risk", ""),
                    "anomaly_score": res.get("anomaly_score", ""),
                    "l4_checked": res.get("l4_checked", ""),
                    "similarity_score": res.get("similarity_score", ""),
                    "latency": res.get("latency", 0.0),
                })
                if i == 1 or i % 10 == 0 or i == len(sample):
                    el = time.time() - t0
                    print(f"  {tag} {i}/{len(sample)} ({el/i:.1f}s/q)", flush=True)
        save_csv(full_rows, "phase3", "A20_real_query_full_pipeline.csv")

        for tag in ("securerag", "baseline"):
            rs = [r for r in full_rows if r["run"] == tag]
            lat = [r["latency"] for r in rs]
            fp = sum(1 for r in rs if r["blocked"])
            result[tag] = {
                "n": len(rs), "blocked": fp,
                "fpr_full_pipeline_pct": round(100 * fp / len(rs), 2),
                "latency_mean_s": round(statistics.mean(lat), 3),
                "latency_median_s": round(statistics.median(lat), 3),
                "latency_std_s": round(statistics.pstdev(lat), 3),
            }
        a, b = result["securerag"], result["baseline"]
        result["A6_legitimate_only_overhead"] = {
            "baseline_mean_s": b["latency_mean_s"],
            "securerag_mean_s": a["latency_mean_s"],
            "overhead_s": round(a["latency_mean_s"] - b["latency_mean_s"], 3),
            "overhead_pct": round(100 * (a["latency_mean_s"] - b["latency_mean_s"])
                                  / b["latency_mean_s"], 2),
            "reading": "This is what a legitimate user pays. The 61.3% figure in "
                       "the thesis is a whole-batch average over a set that is "
                       "75% attacks, most of them blocked before generation.",
        }
        print(f"\nA-6  legitimate queries only: baseline {b['latency_mean_s']}s  "
              f"vs SecureRAG {a['latency_mean_s']}s  "
              f"=> overhead {result['A6_legitimate_only_overhead']['overhead_pct']}%")

    save_json(result, "phase3", "A20_A6_summary.json")
    print("\nPhase 3 complete.")


if __name__ == "__main__":
    main()
