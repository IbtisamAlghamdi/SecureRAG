#!/usr/bin/env python3
"""
run_external_eval.py
---------------------
Runs the external validation set (eval_set.json, built from BIPIA) directly
through src.pipeline.SecureRAG -- exactly the same way thesis_evaluation.py
does it (rag.run(query) -> flag/layer/risk/latency).

Usage:
    conda activate RAG
    python3 run_external_eval.py --model Mistral-7B
    (omit --model to be prompted interactively)
"""

import argparse
import sys
import os
import json
import csv
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import settings
from src.pipeline import SecureRAG  # same import used in thesis_evaluation.py
from model_select import add_model_arg, resolve_model, safe_filename

SCRIPT_DIR = Path(__file__).parent
EVAL_SET_PATH = SCRIPT_DIR / "eval_set.json"


def load_eval_set():
    if not EVAL_SET_PATH.exists():
        raise FileNotFoundError(
            f"{EVAL_SET_PATH} not found -- run build_eval_set.py first and "
            f"copy the output next to this file."
        )
    return json.load(open(EVAL_SET_PATH, encoding="utf-8"))


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    add_model_arg(parser)
    parser.add_argument("--limit", type=int, default=None,
                         help="Only run the first N samples (fast diagnostic subset). "
                              "eval_set.json is pre-shuffled by build_eval_set.py, so this "
                              "is already a random cross-section of attack categories, not "
                              "just the first ones built.")
    args = parser.parse_args()
    selected_model = resolve_model(args.model)
    suffix = safe_filename(selected_model)
    if args.limit:
        suffix += f"__subset{args.limit}"
    results_csv_path = SCRIPT_DIR / f"bipia_external_results__{suffix}.csv"
    summary_json_path = SCRIPT_DIR / f"bipia_external_summary__{suffix}.json"

    samples = load_eval_set()
    if args.limit:
        samples = samples[:args.limit]
    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
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

        # DIAGNOSTIC (added after the 98% external-ASR collapse following the
        # SEMANTIC_THRESHOLD 0.45->0.15 fix): mirrors the columns added to
        # run_external_fpr_eval.py so both sides of the trade-off can be
        # compared on the same footing. anomaly_score tells us whether L3 is
        # even close to flagging attacks that reach the model; similarity_score
        # (only populated for cases that reach L4, i.e. risk HIGH/MEDIUM or
        # anomaly_score > 0) tells us whether real attack responses are, in
        # fact, staying above 0.15 -- the mechanism to confirm/deny before
        # touching the threshold again.
        sim_score = res.get("similarity_score", None)
        l4_checked = res.get("l4_checked", res.get("flag") == "semantic")
        response_snippet = (res.get("response") or "")[:200]

        results.append({
            "id": sample["id"],
            "attack_category": sample["attack_category"],
            "position": sample["position"],
            "blocked": blocked,
            "flag": res.get("flag", ""),
            "blocking_layer": layer,
            "risk_level": res.get("risk", ""),
            "anomaly_score": res.get("anomaly_score", ""),
            "l4_checked": l4_checked,
            "similarity_score": sim_score,
            "latency_sec": elapsed,
            "response_snippet": response_snippet,
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
    with open(results_csv_path, "w", newline="", encoding="utf-8") as f:
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
        "model": selected_model,
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
            "note": "see outputs/thesis_v2/<model>/thesis_results.json for this model's own internal run",
        },
    }
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nFull details:  {results_csv_path}")
    print(f"Summary JSON:  {summary_json_path}")
    print(f"\nTable ready for the paper (External Validation section, model={selected_model}):")
    print(f"  | Dataset                     | ASR            | n     |")
    print(f"  | Internal (self-generated)   | see thesis_v2  | 1,001 |")
    print(f"  | BIPIA external (Microsoft)  | {asr_external:.2f}%         | {n}   |")


if __name__ == "__main__":
    run()