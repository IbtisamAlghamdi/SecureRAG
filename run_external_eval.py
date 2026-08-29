#!/usr/bin/env python3
"""run_external_eval.py --------------------- Runs the external validation set (eval_set.json."""

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
from src.defenses.semantic.semantic_detector import query_response_similarity
from model_select import add_model_arg, resolve_model, safe_filename

SCRIPT_DIR = Path(__file__).parent
EVAL_SET_PATH = SCRIPT_DIR / "eval_set.json"

def load_eval_set(path: Path = EVAL_SET_PATH):
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found -- run build_eval_set.py first and "
            f"copy the output next to this file."
        )
    return json.load(open(path, encoding="utf-8"))

def run():
    parser = argparse.ArgumentParser(description=__doc__)
    add_model_arg(parser)
    parser.add_argument("--limit", type=int, default=None,
                         help="Only run the first N samples (fast diagnostic subset). "
                              "eval_set.json is pre-shuffled by build_eval_set.py, so this "
                              "is already a random cross-section of attack categories, not "
                              "just the first ones built. With --category set, --limit caps "
                              "the FILTERED count instead.")
    # ADDED: a plain --limit N on ~29 roughly-equal categories (~34 each)
    # gives only N/29 samples per category on average -- too thin to check
    # a SPECIFIC category's detection rate changed (e.g. after a fix
    # targeting only certain categories) without a large N. --category lets
    # you test exactly the categories a change was meant to affect.
    parser.add_argument("--category", type=str, default=None,
                         help="Comma-separated attack_category values to run (matches "
                              "eval_set.json's attack_category field exactly, case-sensitive). "
                              "e.g. --category \"Business Intelligence,Content Creation,"
                              "Conversational Agent,Learning and Tutoring,Programming Help,"
                              "Research Assistance,Task Automation,Information Retrieval,"
                              "Sentiment Analysis\" runs only the 9 categories with no "
                              "self-referential injection phrasing (see OUTPUT_HIJACK_PATTERNS' "
                              "docstring in rule_filter.py).")
    # ADDED: this was hardcoded to eval_set.json -- no way to point it at a
    # different attack/document recombination (e.g. build_eval_set.py --seed 7's
    # eval_set_seed7.json) without editing the script. Same underlying BIPIA
    # attack strings either way -- this only lets you check whether the
    # reported External ASR depends on which document/position each attack
    # happened to land on in the default eval_set.json.
    parser.add_argument("--file", type=str, default=None,
                         help="Path to an eval set JSON file to run instead of "
                              "eval_set.json (same schema). e.g. "
                              "--file eval_set_seed7.json")
    args = parser.parse_args()
    selected_model = resolve_model(args.model)
    eval_path = Path(args.file) if args.file else EVAL_SET_PATH
    suffix = safe_filename(selected_model)
    if args.file:
        suffix += f"__{eval_path.stem}"
    if args.category:
        suffix += "__catfilter"
    if args.limit:
        suffix += f"__subset{args.limit}"
    results_csv_path = SCRIPT_DIR / f"bipia_external_results__{suffix}.csv"
    summary_json_path = SCRIPT_DIR / f"bipia_external_summary__{suffix}.json"

    samples = load_eval_set(eval_path)
    if args.category:
        wanted = {c.strip() for c in args.category.split(",")}
        samples = [s for s in samples if s["attack_category"] in wanted]
        unknown = wanted - {s["attack_category"] for s in samples}
        if unknown:
            print(f"WARNING: no samples matched these --category values "
                  f"(check spelling/capitalization): {sorted(unknown)}")
        print(f"Category filter applied: {len(samples)} samples across {len(wanted - unknown)} categories")
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
        qr_sim = res.get("query_response_similarity", None)
        l4_checked = res.get("l4_checked", res.get("flag") == "semantic")
        # response_snippet stays capped for human readability. It must NOT be
        # what compliance scoring reads -- see response_full below.
        #
        # FIXED: classify_true_compliance.py used to score this 500-char
        # snippet, and 297/567 (52.4%) of reached-model responses hit that
        # cap, i.e. were cut. The cut is not neutral: benign_question_
        # similarity averaged 0.2966 on truncated responses versus 0.5556 on
        # untruncated ones. Since the verdict is
        # (attack_similarity - benign_similarity) > margin, halving the
        # benign term systematically widens the gap and over-reports
        # compliance. Measured consequence: compliance among reached-model
        # samples was 27.21% (154/566) scored on truncated text, against
        # 4.55% (1/22) scored on full text through the identical pipeline --
        # 95% CIs [23.7%, 31.0%] and [0.8%, 21.8%], which do not overlap.
        # The full text is now stored separately so the scorer never sees a
        # truncated response.
        full_response = res.get("response") or ""
        response_snippet = full_response[:500]

        # ADDED: does the ATTACK-SIDE run measure whether the model actually
        # served the user's real request, not just "reached the model"?
        # (Reviewer concern: "reaching the model is not necessarily a
        # successful prompt injection" -- a response can clear every layer
        # and still be a harmless answer to the ORIGINAL question, with the
        # injected instruction ignored.) benign_question_similarity is the
        # cosine similarity between the model's response and
        # sample["benign_question"] -- the real, uninjected question BIPIA
        # paired with this document. High similarity => the response stayed
        # anchored to what the user actually asked (the hijack largely
        # failed in practice, even if it wasn't blocked). Low similarity =>
        # the response drifted toward the injected topic instead (the hijack
        # actually worked). Only computed for responses that reached the
        # model (not for blocked queries, which have no real generation to
        # compare) and only when the sample provides a benign_question
        # (eval_set.json always does; guarded here so this script doesn't
        # assume that shape for every possible caller).
        benign_q_sim = None
        if not blocked and res.get("response") and sample.get("benign_question"):
            try:
                benign_q_sim = round(
                    query_response_similarity(
                        sample["benign_question"], res["response"], rag.embedder
                    ), 4
                )
            except Exception:
                benign_q_sim = None

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
            "query_response_similarity": qr_sim,
            "benign_question_similarity": benign_q_sim,
            # ADDED: pipeline.py sets result["violation_type"] on every L2
            # block, but it was never logged -- blocking_layer only ever said
            # "rules", so the CSV could not show WHICH tier fired. A separate
            # 40-sample probe found all 18 external blocks came from
            # output_hijack alone; without this column that fact is not
            # recoverable from the run's own output.
            "violation_type": res.get("violation_type", ""),
            # ADDED: makes the results file self-contained. Compliance
            # scoring recovers the injected instruction through this key;
            # relying on an id-join into eval_set.json instead means a
            # regenerated eval set (different --seed) would silently pair
            # responses with the wrong attack text.
            "attack_name": sample.get("attack_name", ""),
            "latency_sec": elapsed,
            "response_snippet": response_snippet,
            "response_full": full_response,
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

    # ADDED: "reached the model" vs "actually hijacked" -- reports the
    # benign_question_similarity distribution for the reached-model subset
    # (measurement only, no invented cutoff/threshold -- see the field's
    # docstring in this script above). A meaningful blocking/reporting
    # threshold should only be set after this distribution is compared
    # against the same measurement on genuinely clean responses
    # (run_external_fpr_eval.py), the same way SEMANTIC_THRESHOLD was
    # calibrated from real data rather than guessed.
    bq_sims = [r["benign_question_similarity"] for r in results
               if r["benign_question_similarity"] is not None]
    if bq_sims:
        bq_sims_sorted = sorted(bq_sims)
        mid = len(bq_sims_sorted) // 2
        median_bq = bq_sims_sorted[mid] if len(bq_sims_sorted) % 2 else \
            (bq_sims_sorted[mid-1] + bq_sims_sorted[mid]) / 2
        print(f"\nTask-hijack signal (reached-model responses only, n={len(bq_sims)}):")
        print(f"  benign_question_similarity: "
              f"mean={sum(bq_sims)/len(bq_sims):.3f}  "
              f"median={median_bq:.3f}  "
              f"min={min(bq_sims):.3f}  max={max(bq_sims):.3f}")
        print(f"  (measurement only -- no cutoff applied here; see the CSV's "
              f"benign_question_similarity column to inspect individual cases)")

    summary = {
        "model": selected_model,
        "n_samples": n,
        # ADDED: a results file that does not record the thresholds and
        # generation settings it ran under cannot be matched to the code
        # state that produced it once either changes.
        "eval_set_file": str(eval_path.name),
        "anomaly_threshold": settings.get_anomaly_threshold(),
        "semantic_threshold": settings.get_semantic_threshold(),
        "temperature": getattr(settings, "TEMPERATURE", None),
        "max_new_tokens": getattr(settings, "MAX_NEW_TOKENS", None),
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