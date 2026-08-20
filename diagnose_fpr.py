#!/usr/bin/env python3
"""
diagnose_fpr.py
-----------------
Runs ONLY the 333 benign queries through SecureRAG once (fast -- not the
full 5-run x 1,334-query evaluation) and logs exactly which query got
blocked and by which layer, so false positives can be inspected directly.

*** Run this AFTER the current thesis_evaluation.py run finishes (don't
    run both at once -- loading the model twice will slow both down). ***

Usage:
    conda activate RAG
    python3 diagnose_fpr.py --model Mistral-7B
    python3 diagnose_fpr.py --model Llama-3.2-3B
    python3 diagnose_fpr.py --model Phi-3.5-Mini
    (omit --model to be prompted interactively)
"""

import argparse
import sys
import os
import csv
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import settings
from src.pipeline import SecureRAG
from src.attacks.generator import RealisticAttackGenerator
from model_select import add_model_arg, resolve_model, safe_filename

BENIGN_COUNT = 333
SEED = 42


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    add_model_arg(parser)
    args = parser.parse_args()
    selected_model = resolve_model(args.model)
    out_csv = f"benign_fpr_diagnosis__{safe_filename(selected_model)}.csv"

    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)

    print("Building benign query set (same method as thesis_evaluation.py)...")
    gen = RealisticAttackGenerator()
    random.seed(SEED)
    # FIXED: was random.sample(gen.benign_queries, k=BENIGN_COUNT) against a
    # static pre-written list. generate_benign_batch() builds BENIGN_COUNT
    # queries dynamically from template x topic pools, zero duplicates.
    benign = gen.generate_benign_batch(BENIGN_COUNT)

    print(f"Running {len(benign)} benign queries...\n")

    results = []
    fp_count = 0
    for i, query in enumerate(benign, 1):
        res = rag.run(query)
        is_blocked = res['flag'] not in ['clean', 'baseline', 'error']
        results.append({
            "query": query,
            "blocked": is_blocked,
            # ADDED: threshold_sensitivity_analysis.py expects this exact
            # column name (matching run_external_fpr_eval.py's convention)
            # -- every block on a benign-only set is a false positive by
            # definition, so this just mirrors "blocked".
            "false_positive": is_blocked,
            "flag": res.get('flag', ''),
            "layer": res.get('layer', ''),
            "risk": res.get('risk', ''),
            # ADDED: without these, a SEMANTIC_THRESHOLD sensitivity sweep
            # (threshold_sensitivity_analysis.py) can only ever be run
            # against the EXTERNAL BIPIA benign set -- there was no way to
            # check whether a candidate threshold is safe for the INTERNAL
            # benign generator specifically before committing it to
            # settings.py. Same columns run_external_fpr_eval.py already
            # logs, so both sides can be swept with the same tool.
            "l4_checked": res.get('l4_checked', False),
            "similarity_score": res.get('similarity_score', ''),
            "query_response_similarity": res.get('query_response_similarity', ''),
            "latency": res.get('latency', 0.0),
        })
        if is_blocked:
            fp_count += 1
        if i % 20 == 0 or i == len(benign):
            print(f"  [{i}/{len(benign)}] processing... (FP so far: {fp_count})", end='\r')

    print(f"\n\nTotal false positives: {fp_count}/{len(benign)} "
          f"({100*fp_count/len(benign):.2f}%)\n")

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"Full details saved to: {out_csv}\n")

    print("=== False positives (blocked benign queries) ===")
    for r in results:
        if r["blocked"]:
            print(f"  [{r['layer']:15s}] risk={r['risk']:8s} | {r['query'][:70]}")


if __name__ == "__main__":
    run()