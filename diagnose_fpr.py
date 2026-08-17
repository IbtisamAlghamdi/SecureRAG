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
    cp diagnose_fpr.py "SecureRAG_Fixed/"
    cd "SecureRAG_Fixed"
    python3 diagnose_fpr.py
"""

import sys
import os
import csv
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import SecureRAG
from src.attacks.generator import RealisticAttackGenerator

BENIGN_COUNT = 333
SEED = 42
OUT_CSV = "benign_fpr_diagnosis.csv"


def run():
    print("Loading SecureRAG...")
    rag = SecureRAG(enable_defenses=True)

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
            "flag": res.get('flag', ''),
            "layer": res.get('layer', ''),
            "risk": res.get('risk', ''),
            "latency": res.get('latency', 0.0),
        })
        if is_blocked:
            fp_count += 1
        if i % 20 == 0 or i == len(benign):
            print(f"  [{i}/{len(benign)}] processing... (FP so far: {fp_count})", end='\r')

    print(f"\n\nTotal false positives: {fp_count}/{len(benign)} "
          f"({100*fp_count/len(benign):.2f}%)\n")

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"Full details saved to: {OUT_CSV}\n")

    print("=== False positives (blocked benign queries) ===")
    for r in results:
        if r["blocked"]:
            print(f"  [{r['layer']:15s}] risk={r['risk']:8s} | {r['query'][:70]}")


if __name__ == "__main__":
    run()