#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase0b_heldout_and_public.py  --  examiner item A-2
=============================================================
A-2 is the circularity criticism: the same author wrote the attack generator
and the L2/L3 rules. It asks for two distinct things, and this phase does both
at the L0-L3 level (no model, so it runs in minutes):

  (b) held-out templates -- every tier's base-string pool is split in half by
      hash; detection is reported on the DEV half and on the TEST half
      separately. A large gap would mean the rules are fitted to the strings
      they were written against.

  (c) additional public sets -- third-party attacks nobody on this project
      wrote. Tensor Trust (Toyer et al., 2023) is 1,344 attacks written by
      players of a public prompt-injection game; it downloads directly and is
      the strongest available answer to "have test attacks written by a third
      party". HackAPrompt (Schulhoff et al., 2023) is added when its file is
      available locally or HuggingFace is reachable.

AgentDojo is deliberately NOT included, and the reason is reported rather than
omitted: its injections are placed in tool-call results consumed by an agent
loop, a surface SecureRAG does not implement. Running it would measure the
absence of an agent runtime, not the defense.

Usage:  python3 changeb4/phase0b_heldout_and_public.py
        python3 changeb4/phase0b_heldout_and_public.py --hackaprompt-file path.csv
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changeb4.common import run_input_layers, save_json, save_csv, out_dir  # noqa
from changeb4.heldout_templates import SplitAttackGenerator, split_report   # noqa

CACHE = ROOT / "data" / "public_attack_sets"
TT_BASE = ("https://raw.githubusercontent.com/HumanCompatibleAI/"
           "tensor-trust-data/main/benchmarks")
TT_FILES = {
    "tensortrust_hijacking":
        f"{TT_BASE}/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl",
    "tensortrust_extraction":
        f"{TT_BASE}/extraction-robustness/v1/extraction_robustness_dataset.jsonl",
}
HF_HACKAPROMPT = ("https://huggingface.co/datasets/hackaprompt/"
                  "hackaprompt-dataset/resolve/main/hackaprompt.csv")


def fetch(url: str, dest: Path) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        print(f"    downloading {dest.name} ...", flush=True)
        urllib.request.urlretrieve(url, dest)
        return dest.stat().st_size > 0
    except Exception as e:
        print(f"    could not download {dest.name}: {type(e).__name__}: {e}")
        return False


def tally(queries, label):
    c = collections.Counter()
    rows = []
    for q in queries:
        r = run_input_layers(q)
        c[r["blocked_at"] or "reached"] += 1
        rows.append({"set": label, "query": q[:500],
                     "blocked_at": r["blocked_at"] or "",
                     "flag": r["flag"], "risk": r["risk"],
                     "anomaly_score": r["anomaly_score"],
                     "violation_type": r["violation_type"] or "",
                     "l4_gate_open": r["l4_gate_open"]})
    n = len(queries)
    blocked = sum(v for k, v in c.items() if k != "reached")
    return rows, {"n": n, "blocked_pre_l4": blocked,
                  "detection_pre_l4_pct": round(100 * blocked / max(n, 1), 2),
                  "by_layer": dict(c)}


# ── A-2 (b) ────────────────────────────────────────────────────────────────
def heldout_templates(n_per_half=700, seeds=(42, 137, 271)):
    rep = split_report()
    print(f"  base-string pools: {rep['totals']['full']} total -> "
          f"{rep['totals']['dev']} dev / {rep['totals']['test']} test")
    out = {"split": rep, "halves": {}}
    for half in ("dev", "test"):
        g = SplitAttackGenerator(half)
        per_seed, per_cat = [], collections.defaultdict(lambda: [0, 0])
        for s in seeds:
            batch = g.generate_batch(n_per_half, seed=s)
            blocked = 0
            for a in batch:
                r = run_input_layers(a["payload"])
                if r["blocked_at"]:
                    blocked += 1
                    per_cat[a["type"]][1] += 1
                per_cat[a["type"]][0] += 1
            per_seed.append(round(100 * blocked / len(batch), 2))
        import statistics
        out["halves"][half] = {
            "seeds": list(seeds), "per_seed_detection_pct": per_seed,
            "mean": round(statistics.mean(per_seed), 2),
            "std": round(statistics.pstdev(per_seed), 2),
            "per_category_detection_pct": {
                k: round(100 * v[1] / v[0], 1) for k, v in sorted(per_cat.items())},
        }
        print(f"    {half:<4} half: detection(pre-L4) "
              f"{out['halves'][half]['mean']}% +/- {out['halves'][half]['std']}")
    d, t = out["halves"]["dev"]["mean"], out["halves"]["test"]["mean"]
    out["gap_dev_minus_test_pts"] = round(d - t, 2)
    print(f"    gap dev - test = {out['gap_dev_minus_test_pts']} pts")
    return out


# ── A-2 (c) ────────────────────────────────────────────────────────────────
def public_sets(hackaprompt_file=None):
    res, all_rows = {}, []
    for name, url in TT_FILES.items():
        dest = CACHE / f"{name}.jsonl"
        if not fetch(url, dest):
            res[name] = {"available": False, "url": url}
            continue
        qs = []
        for line in dest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            a = (d.get("attack") or "").strip()
            if a:
                qs.append(a)
        rows, stats = tally(qs, name)
        all_rows += rows
        stats.update({"available": True, "source": url,
                      "provenance": "written by third-party players of the "
                                    "public Tensor Trust game"})
        res[name] = stats
        print(f"    {name:<26} {stats['blocked_pre_l4']}/{stats['n']} "
              f"blocked pre-L4 ({stats['detection_pre_l4_pct']}%)")

    hp = Path(hackaprompt_file) if hackaprompt_file else CACHE / "hackaprompt.csv"
    if not hp.exists():
        fetch(HF_HACKAPROMPT, hp)
    if hp.exists() and hp.stat().st_size > 0:
        import csv as _csv
        qs = []
        with open(hp, encoding="utf-8", errors="ignore") as f:
            for r in _csv.DictReader(f):
                v = (r.get("user_input") or r.get("prompt") or
                     r.get("submission") or "").strip()
                if v:
                    qs.append(v)
        if qs:
            if len(qs) > 5000:
                import random as _r
                _r.seed(42)
                qs = _r.sample(qs, 5000)
            rows, stats = tally(qs, "hackaprompt")
            all_rows += rows
            stats.update({"available": True, "source": str(hp),
                          "provenance": "HackAPrompt competition submissions, "
                                        "written by third-party contestants",
                          "note": "sampled to 5,000 if larger"})
            res["hackaprompt"] = stats
            print(f"    {'hackaprompt':<26} {stats['blocked_pre_l4']}/{stats['n']} "
                  f"blocked pre-L4 ({stats['detection_pre_l4_pct']}%)")
    else:
        res["hackaprompt"] = {
            "available": False,
            "how_to_get_it": "huggingface-cli download hackaprompt/"
                             "hackaprompt-dataset --repo-type dataset  (or pass "
                             "--hackaprompt-file <csv>). Blocked networks will "
                             "fail here; the file is the only requirement."}
        print("    hackaprompt                not available "
              "(see how_to_get_it in the JSON)")

    res["agentdojo"] = {
        "available": False, "deliberate": True,
        "reason": "AgentDojo injects into tool-call results inside an agent "
                  "loop. SecureRAG has no agent runtime or tool layer, so the "
                  "benchmark would measure a missing component rather than the "
                  "defense. Reported as out of scope rather than silently "
                  "omitted."}
    return res, all_rows


# ── A-2, the specific claim: "L2 patterns mirror generator categories" ─────
SAME_NAME = {"context_poisoning": "context_poisoning",
             "trust_escalation": "trust_escalation",
             "nested_hiding": "nested_hiding",
             "psychological_manip": "authority_impersonation",
             "indirect_poisoning": "indirect_authorization"}


def tier_crosstab(seeds=(42, 137, 271)):
    """For every generator category, which L2 tier actually blocked it? The
    criticism assumes a category is detected BY THE TIER THAT SHARES ITS NAME.
    That is a testable claim, and this table tests it instead of conceding it."""
    from src.defenses.sanitization.sanitize import sanitize_input   # noqa
    import changeb4.common as cm
    X = collections.defaultdict(collections.Counter)
    tot = collections.Counter()
    for s in seeds:
        for a in cm.make_batch(s)[0]:
            cat = cm.base_tier(a["type"])
            tot[cat] += 1
            r = cm.run_input_layers(a["payload"])
            key = (r["violation_type"] or "?") if r["blocked_at"] == "L2" \
                else (r["blocked_at"] or "reached")
            X[cat][key] += 1
    out = {}
    print(f"    {'generator category':<24}{'n':>5}{'by same-name tier':>20}   top blockers")
    for cat in sorted(tot, key=lambda c: -tot[c]):
        same = SAME_NAME.get(cat)
        n = tot[cat]
        share = round(100 * X[cat].get(same, 0) / n, 1) if same else None
        out[cat] = {"n": n, "same_name_l2_tier": same,
                    "blocked_by_same_name_tier_pct": share,
                    "blockers": {k: round(100 * v / n, 1)
                                 for k, v in X[cat].most_common()}}
        top = ", ".join(f"{k} {100*v/n:.0f}%" for k, v in X[cat].most_common(3))
        print(f"    {cat:<24}{n:>5}{(str(share)+'%') if same else '-- none --':>20}   {top}")
    return out


def full_pipeline_public(rows, n, model):
    """Runs a sample of the third-party attacks through the complete pipeline,
    so the reported third-party figure includes L4 rather than stopping at L3."""
    import random, time
    from src.config import settings
    from model_select import resolve_model
    resolve_model(model)
    from src.pipeline import SecureRAG

    random.seed(42)
    sample = random.sample(rows, min(n, len(rows)))
    rag = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
    out, t0 = [], time.time()
    for i, r in enumerate(sample, 1):
        res = rag.run(r["query"])
        blk = res.get("flag") not in ("clean", "baseline", "error")
        out.append({"set": r["set"], "query": r["query"][:500], "blocked": blk,
                    "flag": res.get("flag", ""), "layer": res.get("layer", ""),
                    "risk": res.get("risk", ""),
                    "similarity_score": res.get("similarity_score", ""),
                    "latency": res.get("latency", "")})
        if i == 1 or i % 10 == 0 or i == len(sample):
            el = time.time() - t0
            print(f"      full pipeline {i}/{len(sample)} ({el/i:.1f}s/q)", flush=True)
    save_csv(out, "phase0b", "A2c_public_sets_full_pipeline.csv")
    per = {}
    for s_ in sorted(set(r["set"] for r in out)):
        rs = [r for r in out if r["set"] == s_]
        b = sum(1 for r in rs if r["blocked"])
        per[s_] = {"n": len(rs), "blocked": b,
                   "detection_full_pipeline_pct": round(100 * b / len(rs), 2)}
        print(f"    {s_:<26} {b}/{len(rs)} blocked with L4 "
              f"({per[s_]['detection_full_pipeline_pct']}%)")
    return per


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hackaprompt-file", default=None)
    ap.add_argument("--n-per-half", type=int, default=700)
    ap.add_argument("--full-sample", type=int, default=0,
                    help="also run this many third-party attacks through the "
                         "COMPLETE pipeline (adds L4; needs the model)")
    ap.add_argument("--model", default="Mistral-7B")
    args = ap.parse_args()

    print("=" * 74)
    print("Change-B4 / Phase 0b -- item A-2 (circularity)")
    print("=" * 74)
    print("\n(b) held-out templates")
    ho = heldout_templates(args.n_per_half)
    print("\n(b2) which L2 tier actually blocks each generator category")
    xt = tier_crosstab()
    print("\n(c) third-party public attack sets")
    pub, rows = public_sets(args.hackaprompt_file)
    if rows:
        save_csv(rows, "phase0b", "A2c_public_sets_per_query.csv")

    full = None
    if args.full_sample:
        full = full_pipeline_public(rows, args.full_sample, args.model)

    save_json({"A2b_heldout_templates": ho, "A2b2_tier_crosstab": xt,
               "A2c_public_sets": pub, "A2c_full_pipeline": full},
              "phase0b", "A2_results.json")
    print("\nPhase 0b complete.")


if __name__ == "__main__":
    main()
