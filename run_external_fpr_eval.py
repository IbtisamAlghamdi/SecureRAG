#!/usr/bin/env python3
"""
run_external_fpr_eval.py
--------------------------
Runs the external benign validation set (fpr_set.json, built from clean
BIPIA documents) directly through src.pipeline.SecureRAG, exactly the
same call pattern used in run_external_eval.py and thesis_evaluation.py
(rag.run(query) -> flag/layer/risk/latency).

Every sample here is genuinely benign (no attack inserted). Any query
that gets blocked is, by definition, a FALSE POSITIVE.

*** Place this file inside the project folder "SecureRAG_Fixed 2" (next to
    thesis_evaluation.py and chat.py) before running, so the import works. ***

Usage:
    conda activate RAG
    cp run_external_fpr_eval.py "SecureRAG_Fixed 2/"
    cp fpr_set.json "SecureRAG_Fixed 2/"
    cd "SecureRAG_Fixed 2"
    python3 run_external_fpr_eval.py
"""

import sys
import os
import json
import csv
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import SecureRAG  # same import used in thesis_evaluation.py

SCRIPT_DIR = Path(__file__).parent
FPR_SET_PATH = SCRIPT_DIR / "fpr_set.json"
RESULTS_CSV_PATH = SCRIPT_DIR / "bipia_external_fpr_results.csv"
SUMMARY_JSON_PATH = SCRIPT_DIR / "bipia_external_fpr_summary.json"


def load_fpr_set():
    if not FPR_SET_PATH.exists():
        raise FileNotFoundError(
            f"{FPR_SET_PATH} not found -- run build_fpr_set.py first and "
            f"copy the output next to this file."
        )
    return json.load(open(FPR_SET_PATH, encoding="utf-8"))


def run():
    samples = load_fpr_set()
    print("Loading SecureRAG (same as thesis_evaluation.py)...")
    rag = SecureRAG(enable_defenses=True)
    print(f"Running {len(samples)} benign external BIPIA samples...\n")

    results = []
    layer_counts = defaultdict(int)
    type_stats = defaultdict(lambda: {"total": 0, "false_positives": 0})
    total_false_positives = 0
    total_latency = 0.0
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        res = rag.run(sample["combined_query"])

        # Same logic as run_external_eval.py:
        # blocked = flag not in ['clean', 'baseline', 'error']
        # Since every sample here is benign, "blocked" == false positive.
        blocked = res.get("flag") not in ["clean", "baseline", "error"]
        layer = res.get("layer", "none")
        if layer == "none" and not blocked:
            layer = "NONE (passed correctly)"

        elapsed = res.get("latency", 0.0)

        results.append({
            "id": sample["id"],
            "source_type": sample["source_type"],
            "false_positive": blocked,
            "flag": res.get("flag", ""),
            "blocking_layer": layer,
            "risk_level": res.get("risk", ""),
            "latency_sec": elapsed,
        })

        layer_counts[layer] += 1
        t = sample["source_type"]
        type_stats[t]["total"] += 1
        if blocked:
            type_stats[t]["false_positives"] += 1
            total_false_positives += 1
        total_latency += elapsed

        if i % 20 == 0 or i == total:
            print(f"  [{i}/{total}] processing...", end="\r")

    print(f"  [{total}/{total}] done                    \n")

    # ------------ save detailed results ------------
    with open(RESULTS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    # ------------ summary stats ------------
    n = len(samples)
    fpr = 100 * total_false_positives / n
    avg_latency = total_latency / n

    print("=" * 60)
    print("External False Positive Rate Summary -- BIPIA (Microsoft)")
    print("=" * 60)
    print(f"Sample count:            {n}")
    print(f"False Positive Rate:     {fpr:.2f}%  ({total_false_positives}/{n})")
    print(f"Average latency:         {avg_latency:.2f}s")

    print("\nOutcome distribution by layer/flag:")
    for layer, count in sorted(layer_counts.items(), key=lambda x: -x[1]):
        print(f"  {layer:30s} {count:5d}  ({100*count/n:.1f}%)")

    print("\nFalse positive rate by document source type:")
    for t, stats in sorted(type_stats.items()):
        rate = 100 * stats["false_positives"] / stats["total"]
        print(f"  {t:15s} {rate:5.1f}%  ({stats['false_positives']}/{stats['total']})")

    summary = {
        "n_samples": n,
        "false_positive_rate_pct": round(fpr, 2),
        "false_positive_count": total_false_positives,
        "avg_latency_sec": round(avg_latency, 3),
        "layer_distribution": dict(layer_counts),
        "fpr_by_source_type": {
            t: round(100 * s["false_positives"] / s["total"], 1)
            for t, s in type_stats.items()
        },
        "internal_baseline_for_comparison": {
            "FPR_pct": 0.0, "n_legitimate": 333
        },
    }
    with open(SUMMARY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nFull details:  {RESULTS_CSV_PATH}")
    print(f"Summary JSON:  {SUMMARY_JSON_PATH}")
    print(f"\nTable ready for the paper (External Validation section):")
    print(f"  | Dataset                     | FPR    | n     |")
    print(f"  | Internal (self-generated)   | 0.00%  | 333   |")
    print(f"  | BIPIA external (Microsoft)  | {fpr:.2f}%  | {n}   |")


if __name__ == "__main__":
    run()
