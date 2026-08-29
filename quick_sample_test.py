#!/usr/bin/env python3
"""
quick_sample_test.py
----------------------
Fast, stratified-random sanity check for the border-strings + reminder
defense added to pipeline.py's _get_rag_context() -- does NOT touch that
code at all, this is a read-only test harness. Runs 50 internal attack
samples (RealisticAttackGenerator, all 8 tiers) + 50 external attack
samples (eval_set.json/BIPIA, all attack_category values) through the real
model, instead of the full 1,001 / 986, so you get a signal in ~100 model
calls instead of ~2,000.

STRATIFIED, not plain random: with ~8 internal tiers and ~29 external
categories, a plain random draw of 50 could easily miss a whole category
entirely (50/29 < 2 on average). This instead guarantees every tier/
category gets AT LEAST one sample, then fills the rest of the 50 randomly,
so a category-specific effect (like the border-strings fix, aimed
specifically at BIPIA's 9 no-self-reference categories) can't hide in an
unlucky draw.

This is a QUICK SIGNAL, not a replacement for the full run -- 50 samples
per category average out to 1-2 each, too few for a precise per-category
rate. Treat a clear swing (e.g. a previously-0% category now blocking
several of its 1-2 samples) as "worth the full run to confirm", and a
still-flat 0% as "worth investigating before the full run", not as final
numbers either way.

Usage:
    python3 quick_sample_test.py --model Mistral-7B --seed 1
"""

import argparse
import csv
import json
import random
from collections import defaultdict
from pathlib import Path

from src.config import settings
from src.pipeline import SecureRAG
from src.attacks.generator import RealisticAttackGenerator
from model_select import add_model_arg, resolve_model, safe_filename

SCRIPT_DIR = Path(__file__).parent
EVAL_SET_PATH = SCRIPT_DIR / "eval_set.json"
N_INTERNAL = 50
N_EXTERNAL = 50

INTERNAL_TIERS = [
    "token_smuggling", "conversational_drift", "indirect_poisoning",
    "semantic_camouflage", "context_poisoning", "psychological_manipulation",
    "nested_hiding", "trust_escalation",
]


def stratified_sample(items_by_group: dict, n_total: int, rng: random.Random) -> list:
    """Guarantee >=1 item per group (if the group is non-empty), then fill
    the remainder randomly across all groups. Returns a flat, shuffled list
    of (group, item) tuples."""
    groups = list(items_by_group.keys())
    picked = []
    remaining_pool = []

    for g in groups:
        pool = list(items_by_group[g])
        rng.shuffle(pool)
        if pool:
            picked.append((g, pool.pop()))
        remaining_pool.extend((g, x) for x in pool)

    if len(picked) > n_total:
        # more groups than samples requested -- just take a random subset
        # of the one-per-group picks
        rng.shuffle(picked)
        return picked[:n_total]

    need = n_total - len(picked)
    rng.shuffle(remaining_pool)
    picked.extend(remaining_pool[:need])
    rng.shuffle(picked)
    return picked


def build_internal_sample(rng: random.Random) -> list:
    gen = RealisticAttackGenerator()
    by_tier = {t: getattr(gen, t) for t in INTERNAL_TIERS}
    sample = stratified_sample(by_tier, N_INTERNAL, rng)
    return [{"category": tier, "query": query} for tier, query in sample]


def build_external_sample(rng: random.Random) -> list:
    if not EVAL_SET_PATH.exists():
        print(f"ERROR: {EVAL_SET_PATH} not found.")
        return []
    eval_set = json.load(open(EVAL_SET_PATH, encoding="utf-8"))
    by_cat = defaultdict(list)
    for s in eval_set:
        by_cat[s["attack_category"]].append(s)
    sample = stratified_sample(by_cat, N_EXTERNAL, rng)
    return [{"category": cat, "query": s["combined_query"], "id": s["id"]}
            for cat, s in sample]


def run_batch(rag, samples, label):
    results = []
    blocked = 0
    for i, item in enumerate(samples, 1):
        res = rag.run(item["query"])
        is_blocked = res.get("flag") not in ("clean", "baseline", "error")
        if is_blocked:
            blocked += 1
        results.append({
            "category": item["category"],
            "blocked": is_blocked,
            "flag": res.get("flag", ""),
            "latency": res.get("latency", 0.0),
        })
        print(f"  [{label} {i}/{len(samples)}] {item['category']:30s} "
              f"{'BLOCKED' if is_blocked else 'reached model'}")
    return results, blocked


def print_per_category(results, label):
    by_cat = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in results:
        by_cat[r["category"]]["total"] += 1
        if r["blocked"]:
            by_cat[r["category"]]["blocked"] += 1
    print(f"\n=== {label}: per-category ({len(by_cat)} categories covered) ===")
    for cat, s in sorted(by_cat.items()):
        rate = 100 * s["blocked"] / s["total"]
        print(f"  {cat:32s} {s['blocked']}/{s['total']:2d}  ({rate:.0f}% blocked)")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_model_arg(ap)
    ap.add_argument("--seed", type=int, default=1,
                     help="random seed for the stratified sample (default 1). "
                          "Use a new seed for a different random draw.")
    args = ap.parse_args()
    selected_model = resolve_model(args.model)
    rng = random.Random(args.seed)

    print("Building stratified samples (all categories/tiers represented)...")
    internal = build_internal_sample(rng)
    external = build_external_sample(rng)
    print(f"Internal: {len(internal)} samples across "
          f"{len(set(s['category'] for s in internal))} tiers")
    print(f"External: {len(external)} samples across "
          f"{len(set(s['category'] for s in external))} categories\n")

    print(f"Loading SecureRAG ({selected_model})...")
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)

    print(f"\nRunning {len(internal)} internal + {len(external)} external "
          f"({len(internal)+len(external)} total model calls)...\n")

    internal_results, internal_blocked = run_batch(rag, internal, "internal")
    external_results, external_blocked = run_batch(rag, external, "external")

    internal_asr = 100 * (len(internal) - internal_blocked) / len(internal)
    external_asr = 100 * (len(external) - external_blocked) / len(external)

    print(f"\n{'='*60}")
    print(f"Internal quick-sample ASR: {internal_asr:.2f}%  "
          f"({internal_blocked}/{len(internal)} blocked)")
    print(f"External quick-sample ASR: {external_asr:.2f}%  "
          f"({external_blocked}/{len(external)} blocked)")
    print(f"{'='*60}")

    print_per_category(internal_results, "Internal")
    print_per_category(external_results, "External")

    suffix = safe_filename(selected_model)
    out_path = SCRIPT_DIR / f"quick_sample_test__{suffix}__seed{args.seed}.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "category", "blocked", "flag", "latency"])
        writer.writeheader()
        for r in internal_results:
            writer.writerow({"source": "internal", **r})
        for r in external_results:
            writer.writerow({"source": "external", **r})
    print(f"\nDetail saved to: {out_path}")


if __name__ == "__main__":
    main()
