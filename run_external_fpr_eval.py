#!/usr/bin/env python3
"""run_external_fpr_eval.py -------------------------- Runs the external benign validation set."""

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
FPR_SET_PATH = SCRIPT_DIR / "fpr_set.json"

def load_fpr_set(path: Path):
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found -- run build_fpr_set.py (or "
            f"build_fresh_holdout_fpr.py for a --file target) first."
        )
    return json.load(open(path, encoding="utf-8"))

def run():
    parser = argparse.ArgumentParser(description=__doc__)
    add_model_arg(parser)
    parser.add_argument("--limit", type=int, default=None,
                         help="Only run the first N samples (fast diagnostic subset).")
    parser.add_argument("--source-type", choices=["email", "table"], default=None,
                         help="Only run samples of this document type.")
    # ADDED: this was hardcoded to fpr_set.json -- no way to point it at a
    # different sample file (e.g. build_fresh_holdout_fpr.py's
    # fpr_set_holdout_seed<N>.json, which has zero overlap with fpr_set.json
    # and was never used to tune any threshold) without editing the script.
    parser.add_argument("--file", type=str, default=None,
                         help="Path to a benign sample JSON file to run instead of "
                              "fpr_set.json (same schema: id/source_type/combined_query). "
                              "e.g. --file fpr_set_holdout_seed1.json")
    args = parser.parse_args()
    selected_model = resolve_model(args.model)
    fpr_path = Path(args.file) if args.file else FPR_SET_PATH
    suffix = safe_filename(selected_model)
    if args.file:
        suffix += f"__{fpr_path.stem}"
    if args.limit or args.source_type:
        suffix += f"__subset_{args.source_type or 'all'}{args.limit or ''}"
    results_csv_path = SCRIPT_DIR / f"bipia_external_fpr_results__{suffix}.csv"
    summary_json_path = SCRIPT_DIR / f"bipia_external_fpr_summary__{suffix}.json"

    samples = load_fpr_set(fpr_path)
    if args.source_type:
        samples = [s for s in samples if s["source_type"] == args.source_type]
    if args.limit:
        samples = samples[:args.limit]
    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
    print(f"Running {len(samples)} benign external BIPIA samples...\n")

    results = []
    layer_counts = defaultdict(int)
    type_stats = defaultdict(lambda: {"total": 0, "false_positives": 0})
    total_false_positives = 0
    total_latency = 0.0
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        res = rag.run(sample["combined_query"])

        blocked = res.get("flag") not in ["clean", "baseline", "error"]
        layer = res.get("layer", "none")
        if layer == "none" and not blocked:
            layer = "NONE (passed correctly)"

        elapsed = res.get("latency", 0.0)

        # DIAGNOSTIC (added after the semantic-layer FPR spike): for L4
        # blocks specifically, semantic_response_is_suspicious() returns
        # similarity_score == 0.0 exactly when a bare OUTPUT_DANGER_PATTERNS
        # regex matched, or a real cosine value (< SEMANTIC_THRESHOLD) when
        # it was the corpus-similarity check instead. Logging it (plus a
        # response snippet) tells us which mechanism is actually
        # responsible instead of guessing.
        sim_score = res.get("similarity_score", None)
        qr_sim = res.get("query_response_similarity", None)
        l4_checked = res.get("l4_checked", res.get("flag") == "semantic")
        full_response = res.get("response") or ""
        response_snippet = full_response[:500]

        results.append({
            "id": sample["id"],
            "source_type": sample["source_type"],
            "false_positive": blocked,
            "flag": res.get("flag", ""),
            "blocking_layer": layer,
            "risk_level": res.get("risk", ""),
            "anomaly_score": res.get("anomaly_score", ""),
            "l4_checked": l4_checked,
            "similarity_score": sim_score,
            "query_response_similarity": qr_sim,
            # ADDED (mirrors run_external_eval.py): which L2 tier fired, and
            # the untruncated response. The FPR figure itself does not depend
            # on either -- blocking happens inside the pipeline on the full
            # text -- but without them a false positive cannot be diagnosed
            # from this file alone.
            "violation_type": res.get("violation_type", ""),
            "latency_sec": elapsed,
            "response_snippet": response_snippet,
            "response_full": full_response,
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
    with open(results_csv_path, "w", newline="", encoding="utf-8") as f:
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
        "model": selected_model,
        "n_samples": n,
        "benign_set_file": str(fpr_path.name),
        "anomaly_threshold": settings.get_anomaly_threshold(),
        "semantic_threshold": settings.get_semantic_threshold(),
        "temperature": getattr(settings, "TEMPERATURE", None),
        "max_new_tokens": getattr(settings, "MAX_NEW_TOKENS", None),
        "false_positive_rate_pct": round(fpr, 2),
        "false_positive_count": total_false_positives,
        "avg_latency_sec": round(avg_latency, 3),
        "layer_distribution": dict(layer_counts),
        "fpr_by_source_type": {
            t: round(100 * s["false_positives"] / s["total"], 1)
            for t, s in type_stats.items()
        },
        "internal_baseline_for_comparison": {
            "note": "see benign_fpr_diagnosis__<model>.csv for this model's own internal FPR run",
        },
    }
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nFull details:  {results_csv_path}")
    print(f"Summary JSON:  {summary_json_path}")
    print(f"\nTable ready for the paper (External Validation section, model={selected_model}):")
    print(f"  | Dataset                     | FPR            | n     |")
    print(f"  | Internal (self-generated)   | see diagnosis  | 333   |")
    print(f"  | BIPIA external (Microsoft)  | {fpr:.2f}%         | {n}   |")


if __name__ == "__main__":
    run()
