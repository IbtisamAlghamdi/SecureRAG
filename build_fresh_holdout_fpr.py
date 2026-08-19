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

Usage:
    python3 build_fresh_holdout_fpr.py
    python3 run_external_fpr_eval.py --file fpr_set_holdout.json   # if that
        flag exists; otherwise point the eval script at the new file the
        same way it currently points at fpr_set.json.
"""

import json
import random
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
EXISTING_FPR_SET = SCRIPT_DIR / "fpr_set.json"
OUT_PATH = SCRIPT_DIR / "fpr_set_holdout.json"

# Deliberately different from fpr_set.json's own build seed and from
# build_eval_set.py's SEED=42, so this can't accidentally reconstruct the
# same sample even by coincidence.
SEED = 9001
N_SAMPLES = 300


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


def build():
    rng = random.Random(SEED)
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
    if len(fresh_docs) < N_SAMPLES:
        print(f"NOTE: fewer than {N_SAMPLES} fresh documents available -- "
              f"using all {len(fresh_docs)} instead.")

    rng.shuffle(fresh_docs)
    chosen = fresh_docs[:N_SAMPLES]

    samples = []
    for i, (doc, combined_query) in enumerate(chosen):
        samples.append({
            "id": f"bipia_fpr_holdout_{i:05d}",
            "source": "BIPIA (Microsoft, unmodified/clean, NEVER used for threshold tuning)",
            "source_type": "email" if "email" in doc.get("_src", "") else "unknown",
            "combined_query": combined_query,
            "expected_label": "benign",
        })

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    print(f"\nDone: wrote {len(samples)} genuinely fresh benign samples to {OUT_PATH}")
    print("This file has zero overlap with anything used to pick "
          "ANOMALY_THRESHOLD, SEMANTIC_THRESHOLD, or the L3 length-cap. "
          "Report FPR on THIS file as the real held-out number.")


if __name__ == "__main__":
    build()
