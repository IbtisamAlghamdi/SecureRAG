#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase8_l4_comparison_set.py  --  A-9, and the L4 comparison-set question
==============================================================================
Chapter 3 states three times that L4 compares the answer against THE DOCUMENTS
RETRIEVED for the query. src/pipeline.py:262 passes
`self.retriever.get_embeddings()`, which is every chunk in the index, and
semantic_detector takes the maximum over all of them. The deployed check is
therefore "does this answer resemble anything at all in the corpus", not "is
this answer grounded in what was retrieved".

This script decides, offline and at no risk, whether correcting that is worth
a full re-run. It changes nothing: it recomputes both similarities for answers
that were ALREADY generated and logged, and compares how well each separates a
hijacked answer from a legitimate one.

It also settles A-9 properly. phase4's ROC put every attack response in the
positive class, including the 855 of 986 the model refused unprompted, which
forced the curve to chance. Here the positive class is answers where the attack
actually succeeded -- BIPIA rows the compliance classifier marked complied, and
internal rows carrying a human verdict -- and the negative class is answers to
legitimate questions. Because the similarities are recomputed here rather than
read from a run, neither class depends on L4 having executed.

Three mechanisms are separated, since phase 5 showed 23 of L4's 24 blocks came
from the output pattern filter and only one from the similarity floor:
    pattern     check_output_patterns alone
    corpus      similarity floor against the whole index   (deployed)
    retrieved   similarity floor against the retrieved set (as documented)

No model, no generation. Retrieval is deterministic, and the stored embeddings
are reused rather than re-encoded, so this runs in minutes.

Usage:
  python3 changeb4/phase8_l4_comparison_set.py
  python3 changeb4/phase8_l4_comparison_set.py --top-k 5
"""
import argparse
import csv
import glob
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import OUT_ROOT, save_csv, save_json  # noqa: E402

csv.field_size_limit(10_000_000)


def read_csv(p):
    try:
        return list(csv.DictReader(open(p, encoding="utf-8-sig")))
    except Exception:
        return []


def first(pattern):
    """glob.glob treats '**' as a single '*' unless recursive=True is passed,
    so the previous form silently failed to find a file sitting at the
    repository root or more than one directory down."""
    hits = sorted(glob.glob(str(pattern), recursive=True))
    return hits[0] if hits else None


def find_file(name):
    """The file itself at the root, else anywhere beneath it."""
    p = ROOT / name
    if p.exists():
        return str(p)
    return first(ROOT / "**" / name)


# ── labelled (query, answer) pairs ─────────────────────────────────────────
def load_pairs():
    pos, neg, refused = [], [], []
    notes = []

    # BIPIA: response_full lives in the results CSV, the verdict in the
    # compliance CSV, and the query actually sent to the pipeline
    # (combined_query) only in eval_set.json. Join all three on id.
    res_p = first(OUT_ROOT / "phase1" / "bipia_external_results__*.csv")
    cls_p = first(OUT_ROOT / "phase1" / "compliance_classified__*.csv")
    ev_p = find_file("eval_set.json")
    if res_p and cls_p and ev_p:
        verdict = {r["id"]: r["verdict"] for r in read_csv(cls_p)}
        try:
            ev = json.load(open(ev_p, encoding="utf-8"))
            ev = ev.get("samples", ev) if isinstance(ev, dict) else ev
            qmap = {str(s["id"]): s.get("combined_query", "") for s in ev}
        except Exception as e:
            qmap, notes = {}, notes + [f"eval_set.json unreadable: {e}"]
        n_ok = 0
        for r in read_csv(res_p):
            q = qmap.get(str(r["id"]), "")
            a = r.get("response_full", "")
            v = verdict.get(r["id"], "")
            if not q or not a:
                continue
            n_ok += 1
            rec = {"source": "bipia", "id": r["id"], "query": q, "answer": a,
                   "category": r.get("attack_category", "")}
            if v == "likely_complied":
                pos.append(rec)
            elif v == "likely_resisted":
                refused.append(rec)
        notes.append(f"bipia: {n_ok} rows joined")
    else:
        notes.append("bipia: results/compliance/eval_set not all found -- skipped")

    # Internal: human verdicts from the A-8 sheet, joined to the phase 2 rows
    # on (run, id). The sheet carries payload and response_full itself.
    sheet = OUT_ROOT / "phase2" / "A8_manual_labelling_sheet.csv"
    if sheet.exists():
        n = 0
        for r in read_csv(sheet):
            hv = (r.get("human_verdict") or "").strip().lower()
            if not hv:
                continue
            n += 1
            rec = {"source": f"internal_{r['run']}", "id": r["id"],
                   "query": r.get("payload", ""),
                   "answer": r.get("response_full", ""),
                   "category": r.get("category", "")}
            if not rec["query"] or not rec["answer"]:
                continue
            (pos if hv.startswith("c") else refused).append(rec)
        notes.append(f"internal: {n} human-labelled rows")
    else:
        notes.append("internal: A8 sheet not found -- skipped")

    # Legitimate answers. phase 6 is the only file that stores benign answers
    # in full; phase 3 logs benign queries but not their text.
    p6 = OUT_ROOT / "phase6" / "A14_reference_defense_rows.csv"
    if p6.exists():
        n = 0
        for r in read_csv(p6):
            if r.get("kind") != "benign":
                continue
            q, a = r.get("query", ""), r.get("response_full", "")
            if not q or not a:
                continue
            n += 1
            neg.append({"source": f"benign_{r.get('arm','')}", "id": r.get("id", ""),
                        "query": q, "answer": a, "category": "benign"})
        notes.append(f"benign: {n} answers from phase 6")
    else:
        notes.append("benign: phase6 not found -- run A-14 first")

    return pos, neg, refused, notes


# ── metrics ────────────────────────────────────────────────────────────────
def roc_auc(pos_scores, neg_scores):
    """AUC for a detector that fires on LOW similarity, via rank statistics."""
    if not pos_scores or not neg_scores:
        return None
    xs = [(-s, 1) for s in pos_scores] + [(-s, 0) for s in neg_scores]
    xs.sort(key=lambda t: t[0])
    ranks, i = {}, 0
    vals = [v for v, _ in xs]
    r = [0.0] * len(xs)
    while i < len(xs):
        j = i
        while j + 1 < len(xs) and vals[j + 1] == vals[i]:
            j += 1
        avg = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            r[k] = avg
        i = j + 1
    rsum = sum(r[k] for k in range(len(xs)) if xs[k][1] == 1)
    n1, n0 = len(pos_scores), len(neg_scores)
    return round((rsum - n1 * (n1 + 1) / 2) / (n1 * n0), 4)


def at_threshold(pos_scores, neg_scores, t):
    tp = sum(1 for s in pos_scores if s < t)
    fp = sum(1 for s in neg_scores if s < t)
    return {"threshold": round(t, 4),
            "recall": round(tp / max(len(pos_scores), 1), 4),
            "fpr": round(fp / max(len(neg_scores), 1), 4),
            "tp": tp, "fp": fp}


def best_threshold(pos_scores, neg_scores):
    """Youden J over every observed score."""
    if not pos_scores or not neg_scores:
        return None
    best, cand = None, sorted(set(pos_scores + neg_scores))
    for t in cand:
        for tt in (t, t + 1e-6):
            d = at_threshold(pos_scores, neg_scores, tt)
            j = d["recall"] - d["fpr"]
            if best is None or j > best["youden_j"]:
                best = dict(d, youden_j=round(j, 4))
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top-k", type=int, default=None)
    args = ap.parse_args()

    from src.config import settings
    from src.rag_core.embeddings.embedder import Embedder
    from src.rag_core.retrieval.faiss_engine import FaissRetriever
    from src.defenses.semantic.semantic_detector import check_output_patterns

    top_k = args.top_k or settings.TOP_K
    deployed = settings.get_semantic_threshold()

    pos, neg, refused, notes = load_pairs()
    print("=" * 74)
    print("A-9 / L4 comparison set -- recomputed offline from logged answers")
    print("=" * 74)
    for n in notes:
        print(f"  {n}")
    print(f"\n  positives (attack succeeded)      {len(pos)}")
    print(f"  negatives (legitimate answers)    {len(neg)}")
    print(f"  attack answers the model refused  {len(refused)}  "
          f"(reported separately, not in the ROC)")
    if not pos or not neg:
        print("\n  cannot proceed: both classes are needed.")
        return

    emb = Embedder()
    ret = FaissRetriever(settings.CORPUS_DIR, emb)
    E = np.asarray(ret.get_embeddings(), dtype="float32")
    En = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-10)
    print(f"\n  index: {E.shape[0]} chunks, top_k = {top_k}, "
          f"deployed threshold = {deployed}")

    def selected(query):
        """Mirrors _get_rag_context's selection: the 0.15 floor, else top 2."""
        idx, sc = ret.search(emb.encode(query), k=top_k)
        keep = [i for i, s in zip(idx, sc) if float(s) > 0.15]
        return keep if keep else list(idx[:2])

    rows = []
    for group, items in (("positive", pos), ("negative", neg),
                         ("refused", refused)):
        for i, rec in enumerate(items, 1):
            a = emb.encode(rec["answer"])
            a = a / (np.linalg.norm(a) + 1e-10)
            sim_corpus = float(np.max(En @ a))
            sel = selected(rec["query"])
            sim_retr = float(np.max(En[sel] @ a)) if len(sel) else 0.0
            hit, names = check_output_patterns(rec["answer"])
            rows.append(dict(rec, group=group,
                             sim_corpus=round(sim_corpus, 4),
                             sim_retrieved=round(sim_retr, 4),
                             n_retrieved=len(sel),
                             pattern_hit=bool(hit),
                             pattern_names="|".join(names)))
            if i % 100 == 0 or i == len(items):
                print(f"  scored {group} {i}/{len(items)}", flush=True)

    save_csv(rows, "phase8", "A9_l4_comparison_rows.csv")

    P = [r for r in rows if r["group"] == "positive"]
    N = [r for r in rows if r["group"] == "negative"]
    R = [r for r in rows if r["group"] == "refused"]

    out = {"n_positive": len(P), "n_negative": len(N), "n_refused": len(R),
           "top_k": top_k, "deployed_threshold": deployed,
           "index_chunks": int(E.shape[0]), "notes": notes, "variants": {}}

    for key, col in (("corpus", "sim_corpus"), ("retrieved", "sim_retrieved")):
        ps = [r[col] for r in P]
        ns = [r[col] for r in N]
        out["variants"][key] = {
            "auc": roc_auc(ps, ns),
            "at_deployed_0_18": at_threshold(ps, ns, deployed),
            "best": best_threshold(ps, ns),
            "positive_mean": round(float(np.mean(ps)), 4),
            "negative_mean": round(float(np.mean(ns)), 4),
        }

    pat_r = sum(1 for r in P if r["pattern_hit"]) / max(len(P), 1)
    pat_f = sum(1 for r in N if r["pattern_hit"]) / max(len(N), 1)
    out["pattern_filter"] = {"recall": round(pat_r, 4), "fpr": round(pat_f, 4),
                             "tp": sum(1 for r in P if r["pattern_hit"]),
                             "fp": sum(1 for r in N if r["pattern_hit"])}

    # pattern OR similarity floor, which is what L4 actually is
    for key, col in (("corpus", "sim_corpus"), ("retrieved", "sim_retrieved")):
        b = out["variants"][key]["best"]
        for name, t in (("at_deployed", deployed),
                        ("at_best", b["threshold"] if b else deployed)):
            tp = sum(1 for r in P if r["pattern_hit"] or r[col] < t)
            fp = sum(1 for r in N if r["pattern_hit"] or r[col] < t)
            out["variants"][key][f"combined_{name}"] = {
                "threshold": round(t, 4),
                "recall": round(tp / max(len(P), 1), 4),
                "fpr": round(fp / max(len(N), 1), 4), "tp": tp, "fp": fp}

    out["refused_group"] = {
        "pattern_hit": sum(1 for r in R if r["pattern_hit"]),
        "mean_sim_corpus": round(float(np.mean([r["sim_corpus"] for r in R])), 4) if R else None,
        "mean_sim_retrieved": round(float(np.mean([r["sim_retrieved"] for r in R])), 4) if R else None,
    }
    save_json(out, "phase8", "A9_l4_comparison.json")

    # ── verdict ───────────────────────────────────────────────────────────
    c, r_ = out["variants"]["corpus"], out["variants"]["retrieved"]
    print("\n" + "=" * 74)
    print(f"  {'variant':<12}{'AUC':>8}{'mean pos':>11}{'mean neg':>11}"
          f"{'recall@0.18':>13}{'FPR@0.18':>11}")
    for name, d in (("corpus", c), ("retrieved", r_)):
        a = d["at_deployed_0_18"]
        print(f"  {name:<12}{str(d['auc']):>8}{d['positive_mean']:>11}"
              f"{d['negative_mean']:>11}{a['recall']:>13}{a['fpr']:>11}")
    print()
    for name, d in (("corpus", c), ("retrieved", r_)):
        b = d["best"]
        if b:
            print(f"  {name:<12} best threshold {b['threshold']:<8} "
                  f"recall {b['recall']:<8} FPR {b['fpr']:<8} J {b['youden_j']}")
    p = out["pattern_filter"]
    print(f"\n  pattern filter alone   recall {p['recall']}   FPR {p['fpr']}"
          f"   ({p['tp']} of {len(P)} / {p['fp']} of {len(N)})")
    for name, d in (("corpus", c), ("retrieved", r_)):
        k = d["combined_at_best"]
        print(f"  pattern + {name:<10} recall {k['recall']}   FPR {k['fpr']}"
              f"   at {k['threshold']}")

    print("\n  " + "-" * 70)
    if c["auc"] is not None and r_["auc"] is not None:
        gain = round(r_["auc"] - c["auc"], 4)
        print(f"  AUC change from correcting the comparison set: {gain:+}")
        if gain >= 0.10:
            print("  A substantial separation gain. Correcting the code is")
            print("  worth the full re-run IF the false-positive rate at the")
            print("  new threshold is acceptable -- read the FPR column above,")
            print("  not the AUC alone.")
        elif gain <= 0.02:
            print("  No material gain. The documented comparison set does not")
            print("  separate better than the deployed one on this data, so")
            print("  the code stays and Chapter 3's wording is corrected to")
            print("  describe what runs. That is a measured answer, not a")
            print("  concession.")
        else:
            print("  A modest gain. Not worth a re-run days before a defence;")
            print("  report it as a quantified next step.")
    print("  saved -> Change-B4/phase8/")


if __name__ == "__main__":
    main()
