#!/usr/bin/env python3
"""
check_real_query_fpr.py
------------------------
WHY: BenignQueryGenerator's 0/1084 exhaustive false-positive result is not
independent evidence -- CONFIRMED_FALSE_POSITIVES in verify_no_model.py
(the list every regression fix was checked against) is made up of direct
paraphrases of BenignQueryGenerator's own TOPICS_SENSITIVE entries. Same
author, same finite, fully-visible list, both ends. A 0% result there is
expected by construction, not a discovery.

This script checks FPR against data/beir_{nq,scifact,fiqa}_queries.txt --
real questions written by real people (Google search queries, finance-forum
posts, scientific claims), saved automatically by download_datasets.py
alongside the corpus files. Nobody involved in building SecureRAG's
detection patterns wrote or has ever looked at these questions before this
check. This is the genuinely independent internal-domain signal.

Usage:
    python3 check_real_query_fpr.py
(no arguments -- reads whichever of the three query files exist locally)
"""

from pathlib import Path
from src.defenses.rules.rule_filter import rule_based_detector_detailed, quick_high_risk_scan
from src.defenses.sanitization.sanitize import sanitize_input, get_sanitization_report
from src.defenses.anomaly.anomaly_detector import compute_anomaly_score
from src.config import settings

DATA_DIR = Path(__file__).parent / "data"
QUERY_FILES = ["beir_nq_queries.txt", "beir_scifact_queries.txt", "beir_fiqa_queries.txt"]

def ars_prescreen(query):
    try:
        score = quick_high_risk_scan(query)
        threshold = settings.get_anomaly_threshold()
        if score > threshold * 1.8:
            return "HIGH"
        elif score > threshold * 1.0:
            return "MEDIUM"
    except Exception:
        pass
    return "LOW"

def pre_l4_blocked(query):
    risk_level = ars_prescreen(query)
    sanitized = sanitize_input(query)
    rep = get_sanitization_report(query, sanitized)
    if rep["had_template_inj"]:
        return True, "L1_template"
    if rep["had_injection"] or rep["had_base64"]:
        return True, "L1_injection"
    det, vt, rr = rule_based_detector_detailed(sanitized)
    if det:
        return True, f"L2_{vt}"
    score = compute_anomaly_score(query)
    threshold = settings.get_anomaly_threshold()
    eff = threshold * (0.7 if risk_level == "HIGH" else 1.0)
    if score > eff * 2.0:
        return True, "L3_anomaly"
    return False, None

def main():
    found_any = False
    all_fp = []
    all_total = 0

    for fname in QUERY_FILES:
        path = DATA_DIR / fname
        if not path.exists():
            print(f"  (skipping {fname} -- not found locally; run "
                  f"download_datasets.py --dataset <name> first if you want it included)")
            continue
        found_any = True
        queries = [l.strip() for l in open(path, encoding="utf-8") if l.strip()]
        fp = []
        for q in queries:
            blocked, layer = pre_l4_blocked(q)
            if blocked:
                fp.append((layer, q))
        all_fp.extend(fp)
        all_total += len(queries)
        rate = 100 * len(fp) / len(queries) if queries else 0.0
        print(f"{fname}: {len(fp)}/{len(queries)} blocked = {rate:.2f}%")
        for layer, q in fp:
            print(f"    [{layer}] {q[:100]!r}")

    if not found_any:
        print("\nNo query files found under data/. Run e.g.:")
        print("  python3 download_datasets.py --dataset nq")
        print("  python3 download_datasets.py --dataset scifact")
        print("  python3 download_datasets.py --dataset fiqa")
        return

    print()
    if all_total:
        print(f"TOTAL (genuinely independent, real, in-domain queries): "
              f"{len(all_fp)}/{all_total} = {100*len(all_fp)/all_total:.2f}%")
        print("(L0-L3 only -- this is a lower bound; L4 needs the real model "
              "and only ever adds blocks, never removes them, same caveat "
              "as every other pre-model check in this project.)")


if __name__ == "__main__":
    main()
