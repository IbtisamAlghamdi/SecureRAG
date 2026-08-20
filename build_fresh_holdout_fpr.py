#!/usr/bin/env python3
"""
build_fresh_holdout_fpr.py
---------------------------
WHY THIS SCRIPT EXISTS (read before running):

fpr_set.json (n=333, real BIPIA clean emails+tables) was never edited after
it was built -- that part was already verified via git history. But it WAS
used, before this script existed, to CALIBRATE two parts of the defense:

  1. src/defenses/anomaly/anomaly_detector.py's Dimension-1 length/sentence
     scoring cap (commit f17ab49: "found via the real BIPIA external FPR
     run (68.47%, 228/333 false positives)" -- that 228/333 IS this file).
  2. settings.SEMANTIC_THRESHOLD, 0.45 -> 0.15 (commit 4cdf70b, same
     "68.47% -> 70.87%" numbers, same file).

That means reporting "0.00% FPR on fpr_set.json" for those two parameters
is close to reporting training-set accuracy, not held-out test accuracy --
the threshold was picked to make FPR low on exactly this data. This is not
about whether fpr_set.json's CONTENT was tampered with (it wasn't); it's
that the SAME 333 samples served as both tuning signal and reported metric.

WHAT THIS SCRIPT DOES: builds a second, genuinely fresh benign validation
set from the same raw BIPIA source pool (data/email_test.jsonl,
email_train.jsonl, table_test.jsonl, table_train.jsonl -- ~1,100 real
documents total, of which fpr_set.json only ever used 333), explicitly
EXCLUDING any document whose text already appears inside fpr_set.json, so
there is zero overlap with anything used for tuning. Run FPR on the output
of this script, not fpr_set.json, to get a number that hasn't been seen by
any threshold/formula decision. A small non-zero result here (not 0.00%) is
the expected, credible outcome -- do not treat 0.00% on THIS file as a bug
to chase away either; just report whatever it actually is.

ADDED (--seed): reshuffling fpr_set.json's own 333 samples changes nothing
-- FPR is a count, not order-sensitive, and that file only ever has those
333 total, so there is no larger pool inside IT to draw a different random
subset from. --seed instead lets you draw a genuinely different random 333
from the much bigger ~1,100-document raw pool on each run (still excluding
fpr_set.json's original 333 every time), producing
fpr_set_holdout_seed<N>.json so different draws don't overwrite each other.

Usage:
    python3 build_fresh_holdout_fpr.py                  # default seed 9001
    python3 build_fresh_holdout_fpr.py --seed 123        # a different draw
    python3 build_fresh_holdout_fpr.py --seed 123 --n 200  # smaller/faster
    python3 run_external_fpr_eval.py --file fpr_set_holdout_seed123.json   # if
        that flag exists; otherwise point the eval script at the new file
        the same way it currently points at fpr_set.json.
"""

import json
import random
from pathlib import Path

import argparse

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
EXISTING_FPR_SET = SCRIPT_DIR / "fpr_set.json"

# ADDED: --seed lets you pull a genuinely DIFFERENT random 333-query subset
# from the ~1,100-document raw pool on each run (unlike fpr_set.json, which
# only ever has its fixed 333 -- reshuffling that file's own order changes
# nothing, since FPR is a count, not order-sensitive). Each seed still
# excludes everything already used in fpr_set.json, so no seed can ever
# leak back into what was used for threshold tuning. Output filename
# includes the seed so different draws don't overwrite each other.
DEFAULT_SEED = 9001
N_SAMPLES = 333  # matches fpr_set.json's own size, for a direct apples-to-apples comparison


def load_jsonl(path):
    items = []
    if not path.exists():
        return items
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def load_all_raw_documents():
    docs = []
    for fname in ["email_test.jsonl", "email_train.jsonl",
                  "table_test.jsonl", "table_train.jsonl"]:
        for item in load_jsonl(DATA_DIR / fname):
            if item.get("context") and item.get("question"):
                docs.append(item)
    return docs


def already_used_texts():
    """The exact document text already embedded in fpr_set.json's 333
    combined_query fields, so we can exclude any raw document that overlaps
    with what was already used for threshold tuning."""
    if not EXISTING_FPR_SET.exists():
        print(f"WARNING: {EXISTING_FPR_SET} not found -- cannot check for "
              f"overlap, proceeding without exclusion (less rigorous).")
        return set()
    existing = json.load(open(EXISTING_FPR_SET, encoding="utf-8"))
    return {item["combined_query"] for item in existing}


def build(seed: int, n_samples: int):
    rng = random.Random(seed)
    out_path = SCRIPT_DIR / f"fpr_set_holdout_seed{seed}.json"
    all_docs = load_all_raw_documents()
    if not all_docs:
        print(f"ERROR: no raw BIPIA files found under {DATA_DIR}/. "
              f"This script needs email_test.jsonl / email_train.jsonl / "
              f"table_test.jsonl / table_train.jsonl (the same files "
              f"build_eval_set.py uses) to be present locally.")
        return

    used_texts = already_used_texts()
    print(f"Raw documents available: {len(all_docs)}")
    print(f"Already used in fpr_set.json (excluded): checking overlap...")

    fresh_docs = []
    for doc in all_docs:
        combined_query = (
            f"Here is the content of the retrieved document:\n"
            f"{doc['context']}\n\n"
            f"Question: {doc['question']}"
        )
        if combined_query in used_texts:
            continue
        fresh_docs.append((doc, combined_query))

    print(f"Never-before-used documents remaining: {len(fresh_docs)}")
    if len(fresh_docs) < n_samples:
        print(f"NOTE: fewer than {n_samples} fresh documents available -- "
              f"using all {len(fresh_docs)} instead.")

    rng.shuffle(fresh_docs)
    chosen = fresh_docs[:n_samples]

    samples = []
    for i, (doc, combined_query) in enumerate(chosen):
        samples.append({
            "id": f"bipia_fpr_holdout_seed{seed}_{i:05d}",
            "source": "BIPIA (Microsoft, unmodified/clean, NEVER used for threshold tuning)",
            "source_type": "email" if "email" in doc.get("_src", "") else "unknown",
            "combined_query": combined_query,
            "expected_label": "benign",
        })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    print(f"\nDone: wrote {len(samples)} genuinely fresh benign samples to {out_path}")
    print("This file has zero overlap with anything used to pick "
          "ANOMALY_THRESHOLD, SEMANTIC_THRESHOLD, or the L3 length-cap. "
          "Report FPR on THIS file as the real held-out number.")
    print(f"\nWant a DIFFERENT random 333 next time? Just re-run with a new "
          f"--seed (e.g. --seed {seed + 1}) -- each seed draws its own "
          f"random subset of the ~1,100-document pool, still excluding "
          f"fpr_set.json's original 333 every time.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED,
                     help=f"random seed for this draw (default {DEFAULT_SEED}). "
                          f"Use a different value each time you want a genuinely "
                          f"different random 333-query subset -- reusing a seed "
                          f"reproduces the exact same subset (by design, for "
                          f"repeatable reporting).")
    ap.add_argument("--n", type=int, default=N_SAMPLES,
                     help=f"how many queries to draw (default {N_SAMPLES}).")
    args = ap.parse_args()
    build(seed=args.seed, n_samples=args.n)
