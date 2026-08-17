#!/usr/bin/env python3
"""
run_external_eval.py
---------------------
Runs the external validation set (eval_set.json, built from BIPIA) directly
through src.pipeline.SecureRAG -- exactly the same way thesis_evaluation.py
does it (rag.run(query) -> flag/layer/risk/latency).

*** Place this file inside the project folder "SecureRAG_Fixed 2" (next to
    thesis_evaluation.py and chat.py) before running, so the import works. ***

Usage:
    conda activate RAG                  # same environment you already use
    cp run_external_eval.py "SecureRAG_Fixed 2/"
    cp eval_set.json "SecureRAG_Fixed 2/"
    cd "SecureRAG_Fixed 2"
    python3 run_external_eval.py
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
EVAL_SET_PATH = SCRIPT_DIR / "eval_set.json"
RESULTS_CSV_PATH = SCRIPT_DIR / "bipia_external_results.csv"
SUMMARY_JSON_PATH = SCRIPT_DIR / "bipia_external_summary.json"


def load_eval_set():
    if not EVAL_SET_PATH.exists():
        raise FileNotFoundError(
            f"{EVAL_SET_PATH} not found -- run build_eval_set.py first and "
            f"copy the output next to this file."
        )
    return json.load(open(EVAL_SET_PATH, encoding="utf-8"))


def run():
    samples = load_eval_set()
    print("Loading SecureRAG (same as thesis_evaluation.py)...")
    rag = SecureRAG(enable_defenses=True)
    print(f"Running {len(samples)} BIPIA samples...\n")

    results = []
    layer_counts = defaultdict(int)
    category_stats = defaultdict(lambda: {"total": 0, "blocked": 0})
    total_blocked = 0
    total_latency = 0.0
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        res = rag.run(sample["combined_query"])

        # Same logic as thesis_evaluation.py:
        # is_blocked = flag not in ['clean', 'baseline', 'error']
        blocked = res.get("flag") not in ["clean", "baseline", "error"]
        layer = res.get("layer", "none")
        if layer == "none" and not blocked:
            layer = "NONE (reached model)"

        elapsed = res.get("latency", 0.0)

        results.append({
            "id": sample["id"],
            "attack_category": sample["attack_category"],
            "position": sample["position"],
            "blocked": blocked,
            "flag": res.get("flag", ""),
            "blocking_layer": layer,
            "risk_level": res.get("risk", ""),
            "latency_sec": elapsed,
        })

        layer_counts[layer] += 1
        cat = sample["attack_category"]
        category_stats[cat]["total"] += 1
        if blocked:
            category_stats[cat]["blocked"] += 1
            total_blocked += 1
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
    detection_rate = 100 * total_blocked / n
    asr_external = 100 - detection_rate
    avg_latency = total_latency / n

    print("=" * 60)
    print("External Validation Summary -- BIPIA (Microsoft)")
    print("=" * 60)
    print(f"Sample count:            {n}")
    print(f"Detection Rate:          {detection_rate:.2f}%")
    print(f"External ASR:            {asr_external:.2f}%")
    print(f"Average latency:         {avg_latency:.2f}s")

    print("\nBlocking distribution by layer/flag:")
    for layer, count in sorted(layer_counts.items(), key=lambda x: -x[1]):
        print(f"  {layer:30s} {count:5d}  ({100*count/n:.1f}%)")

    print("\nDetection rate by attack category:")
    for cat, stats in sorted(category_stats.items()):
        rate = 100 * stats["blocked"] / stats["total"]
        print(f"  {cat:35s} {rate:5.1f}%  ({stats['blocked']}/{stats['total']})")

    summary = {
        "n_samples": n,
        "detection_rate_pct": round(detection_rate, 2),
        "asr_external_pct": round(asr_external, 2),
        "avg_latency_sec": round(avg_latency, 3),
        "layer_distribution": dict(layer_counts),
        "per_category_detection_rate": {
            cat: round(100 * s["blocked"] / s["total"], 1)
            for cat, s in category_stats.items()
        },
        "internal_baseline_for_comparison": {
            "ASR_pct": 8.96, "FPR_pct": 0.0, "n_attacks": 1001
        },
    }
    with open(SUMMARY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nFull details:  {RESULTS_CSV_PATH}")
    print(f"Summary JSON:  {SUMMARY_JSON_PATH}")
    print(f"\nTable ready for the paper (External Validation section):")
    print(f"  | Dataset                     | ASR    | n     |")
    print(f"  | Internal (self-generated)   | 8.96%  | 1,001 |")
    print(f"  | BIPIA external (Microsoft)  | {asr_external:.2f}%  | {n}   |")


if __name__ == "__main__":
    run()