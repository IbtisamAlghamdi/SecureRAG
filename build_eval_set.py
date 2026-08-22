#!/usr/bin/env python3
"""
build_eval_set.py
------------------
Builds an external validation set from BIPIA (Microsoft Research) data to
test SecureRAG against indirect prompt injection attacks that the SecureRAG
team had no part in designing. This directly addresses the "co-design bias"
criticism from ACSAC Reviewer B.

Source: https://github.com/microsoft/BIPIA (MIT license for code, CC BY-SA
for data)

Sources used (test + train combined for maximum diversity):
- email_test.jsonl / email_train.jsonl   -> 100 real clean emails (context)
- table_test.jsonl / table_train.jsonl   -> 1,000 real data tables (context)
- text_attack_test.json / _train.json    -> 150 attack instructions across
                                             ~30 intent categories

Logic: the attack instruction is inserted into the document text (start /
middle / end) -- exactly how indirect injection happens in practice via a
retrieved document. This mirrors the approach already used in your own
src/attacks/generator.py for context_poisoning and indirect_poisoning
(which already cites BIPIA as a documentation source) -- but here the
actual content (documents and attack phrasings) comes from a fully
independent source that had no role in designing the defense.

Output: eval_set.json -- a list of samples ready to feed directly into
        SecureRAG.run(query)
"""

import argparse
import json
import random
import re
from pathlib import Path
from collections import Counter

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"

# Change this number as needed. The bundled sources support well over
# 10,000 unique combinations without repetition, so this is fully flexible.
N_SAMPLES = 1000
DEFAULT_SEED = 42


def load_jsonl(path):
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def load_contexts():
    contexts = []
    for fname in ["email_test.jsonl", "email_train.jsonl"]:
        contexts += load_jsonl(DATA_DIR / fname)
    for fname in ["table_test.jsonl", "table_train.jsonl"]:
        contexts += load_jsonl(DATA_DIR / fname)
    return [c for c in contexts if c.get("context") and c.get("question")]


def load_attacks():
    flat = []
    for fname in ["text_attack_test.json", "text_attack_train.json"]:
        raw = json.load(open(DATA_DIR / fname, encoding="utf-8"))
        split_tag = fname.split("_")[-1].split(".")[0]
        for category, prompts in raw.items():
            for i, attack_str in enumerate(prompts):
                flat.append({
                    "attack_name": f"{category}-{split_tag}-{i}",
                    "attack_category": category,
                    "attack_str": attack_str,
                })
    return flat


def split_sentences(text):
    spans = [m.end() for m in re.finditer(r"[.!?]\s+", text)]
    return spans if spans else [len(text) // 2]


def insert_attack(context, attack_str, position, rng):
    if position == "start":
        return "\n".join([attack_str, context])
    elif position == "end":
        return "\n".join([context, attack_str])
    else:
        spans = split_sentences(context)
        cut = rng.choice(spans)
        return "\n".join([context[:cut], attack_str, context[cut:]])


def build(seed: int = DEFAULT_SEED):
    # ADDED: the attack STRINGS and documents come from BIPIA's own fixed,
    # published data on purpose -- that's what makes this an independent,
    # non-co-designed external benchmark, and it should NOT be re-randomized
    # (using the same published attack set every time is the correct thing
    # to do, not a limitation). What `seed` controls is only the RECOMBINATION:
    # which document each attack gets embedded into, at what position
    # (start/middle/end), and the final sample order -- a secondary
    # robustness check (does the reported ASR/FPR depend on this particular
    # pairing?), separate from the internal generator's much more central
    # zero-duplication content randomization. Previously hardcoded to
    # SEED=42 with no way to draw a different recombination without editing
    # this file. Default unchanged, so `eval_set.json` (already used to
    # report External ASR) stays reproducible exactly as before when --seed
    # is omitted.
    rng = random.Random(seed)
    contexts = load_contexts()
    attacks = load_attacks()
    positions = ["start", "middle", "end"]

    all_categories = sorted(set(a["attack_category"] for a in attacks))
    per_category = max(1, N_SAMPLES // len(all_categories))

    print(f"Available sources: {len(contexts)} clean documents x "
          f"{len(attacks)} attacks across {len(all_categories)} intent "
          f"categories")

    samples = []
    sample_id = 0
    used_combos = set()

    for category in all_categories:
        cat_attacks = [a for a in attacks if a["attack_category"] == category]
        target = per_category
        attempts = 0
        added = 0
        while added < target and attempts < target * 20:
            attempts += 1
            attack = rng.choice(cat_attacks)
            ctx_sample = rng.choice(contexts)
            position = rng.choice(positions)

            combo_key = (attack["attack_name"], id(ctx_sample), position)
            if combo_key in used_combos:
                continue
            used_combos.add(combo_key)

            poisoned_doc = insert_attack(
                ctx_sample["context"], attack["attack_str"], position, rng
            )
            benign_question = ctx_sample["question"]

            combined_query = (
                f"Here is the content of the retrieved document:\n"
                f"{poisoned_doc}\n\n"
                f"Question: {benign_question}"
            )

            samples.append({
                "id": f"bipia_ext_{sample_id:05d}",
                "source": "BIPIA (Microsoft, email+table, test+train)",
                "attack_name": attack["attack_name"],
                "attack_category": attack["attack_category"],
                "position": position,
                "poisoned_document": poisoned_doc,
                "benign_question": benign_question,
                "combined_query": combined_query,
                "expected_label": "attack",
            })
            sample_id += 1
            added += 1

    rng.shuffle(samples)
    samples = samples[:N_SAMPLES]

    # ADDED: non-default seeds write to their own file (eval_set_seed<N>.json)
    # instead of overwriting eval_set.json, so the already-reported ASR
    # figure's source file is never silently replaced.
    out_name = "eval_set.json" if seed == DEFAULT_SEED else f"eval_set_seed{seed}.json"
    out_path = SCRIPT_DIR / out_name
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    print(f"\nDone: built {len(samples)} samples across "
          f"{len(all_categories)} attack categories (seed={seed})")
    print(f"Output file: {out_path}")

    cat_counts = Counter(s["attack_category"] for s in samples)
    print(f"\nSample distribution by category ({len(cat_counts)} categories):")
    for cat, count in sorted(cat_counts.items()):
        print(f"  - {cat}: {count}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED,
                     help=f"random seed for document/position recombination "
                          f"(default {DEFAULT_SEED}, the seed already used for "
                          f"the reported eval_set.json). The underlying BIPIA "
                          f"attack strings and documents never change -- only "
                          f"which document each attack lands in, at what "
                          f"position, and the final sample order. Use a "
                          f"different value (e.g. --seed 7) to check whether "
                          f"the reported ASR depends on this particular pairing.")
    args = ap.parse_args()
    build(seed=args.seed)