#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase10_offline_items.py  --  examiner items A-6(b), A-15, A-16, A-17
==============================================================================
Four items that need no model, no generation and no retrieval. It reads files
that already exist and does arithmetic, so it is safe to run while a long
evaluation is using the machine.

A-6(b)  "Analyse a realistic attack ratio (1-5%)."
        The thesis reports a 61.3% latency reduction, but 75% of the evaluation
        set is attacks, and a blocked attack costs almost nothing. At a
        realistic attack ratio the same system looks different, and this
        computes the expected per-query latency at 1%, 3% and 5% from
        latencies already measured: attacks from phase 2, where both arms ran
        the same 200 attacks back to back, and legitimate queries from phase 3,
        where both arms ran the same 150 real queries back to back.

A-15    "Add an Experimental Configuration table listing all settings."
        Collects the versions, the model file, the commit and every threshold
        in one place.

A-16    "Explain the actual truncation mechanism."
        all-MiniLM-L6-v2 truncates its input at max_seq_length tokens. The
        corpus is chunked at 800. Whatever lies past the limit is never part of
        the vector, so it can be neither retrieved on nor compared against by
        L4. The limit is read from the cached model config -- no torch import,
        no download. The generation-side context budget is added up too.

A-17    "Add a table of document counts per source."
        Counts the corpus files by source prefix.

Usage:  python3 changeb4/phase10_offline_items.py
"""
import csv
import glob
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import OUT_ROOT, save_json  # noqa: E402

csv.field_size_limit(10_000_000)


def read_csv(p):
    try:
        return list(csv.DictReader(open(p, encoding="utf-8-sig")))
    except Exception:
        return []


def fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def mean(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 3) if xs else None


# ── A-6(b) ────────────────────────────────────────────────────────────────
def attack_ratio():
    out = {"available": False}
    p2 = OUT_ROOT / "phase2" / "A1_internal_compliance_rows.csv"
    p3 = OUT_ROOT / "phase3" / "A20_real_query_full_pipeline.csv"
    if not (p2.exists() and p3.exists()):
        out["note"] = "needs phase2 and phase3"
        return out

    atk = defaultdict(list)
    for r in read_csv(p2):
        atk[r["run"]].append(fnum(r.get("latency")))
    leg = defaultdict(list)
    for r in read_csv(p3):
        leg[r["run"]].append(fnum(r.get("latency")))

    a_base, a_sec = mean(atk.get("baseline", [])), mean(atk.get("securerag", []))
    l_base, l_sec = mean(leg.get("baseline", [])), mean(leg.get("securerag", []))
    if None in (a_base, a_sec, l_base, l_sec):
        out["note"] = "latency columns incomplete"
        return out

    rows = []
    for p in (0.01, 0.03, 0.05, 0.25, 0.75):
        b = p * a_base + (1 - p) * l_base
        s = p * a_sec + (1 - p) * l_sec
        rows.append({"attack_ratio": p,
                     "baseline_s": round(b, 3), "securerag_s": round(s, 3),
                     "overhead_pct": round(100 * (s - b) / b, 2)})
    out.update(available=True,
               measured={"attack_baseline_s": a_base, "attack_securerag_s": a_sec,
                         "legit_baseline_s": l_base, "legit_securerag_s": l_sec,
                         "n_attacks": len(atk.get("baseline", [])),
                         "n_legit": len(leg.get("baseline", []))},
               expected_latency=rows,
               note=("attack latencies come from phase 2, where both arms ran the "
                     "same 200 attacks back to back; legitimate latencies from "
                     "phase 3, same 150 real queries, same session. The 0.75 row "
                     "is the ratio the thesis evaluation set actually has."))
    return out


# ── A-16 ──────────────────────────────────────────────────────────────────
def truncation():
    out = {}
    hits = glob.glob(os.path.expanduser(
        "~/.cache/huggingface/**/sentence_bert_config.json"), recursive=True)
    hits += glob.glob(os.path.expanduser(
        "~/.cache/torch/sentence_transformers/**/sentence_bert_config.json"),
        recursive=True)
    for h in hits:
        if "minilm" in h.lower():
            try:
                cfg = json.load(open(h))
                out["embedder_config"] = h
                out["max_seq_length"] = cfg.get("max_seq_length")
                break
            except Exception:
                pass
    if "max_seq_length" not in out:
        out["max_seq_length"] = None
        out["note"] = ("cached sentence_bert_config.json not found; run "
                       "`python3 -c \"from sentence_transformers import "
                       "SentenceTransformer as S; print(S('all-MiniLM-L6-v2')"
                       ".max_seq_length)\"` when the machine is free")
    try:
        from src.config import settings as S
        chunk = getattr(S, "CHUNK_SIZE", 800)
        overlap = getattr(S, "CHUNK_OVERLAP", 100)
        out["chunk_tokens"] = chunk
        out["chunk_overlap"] = overlap
        m = out.get("max_seq_length")
        if m:
            out["embedded_fraction_of_chunk"] = round(min(m, chunk) / chunk, 3)
            out["tokens_never_embedded_per_chunk"] = max(0, chunk - m)
        out["generation_budget"] = {
            "n_ctx": S.N_CTX,
            "top_k": S.TOP_K,
            "retrieved_tokens_max": S.TOP_K * chunk,
            "system_prompt_tokens_approx": 190,
            "max_output_tokens": getattr(S, "MAX_NEW_TOKENS", 512),
            "total_demand": (S.TOP_K * chunk + 190
                             + getattr(S, "MAX_NEW_TOKENS", 512)),
            "over_budget_by": (S.TOP_K * chunk + 190
                               + getattr(S, "MAX_NEW_TOKENS", 512) - S.N_CTX),
            "note": ("retrieved text + system prompt + reserved output compared "
                     "against n_ctx; a positive over_budget_by is the examiner's "
                     "arithmetic in item A-16, and whatever exceeds the window is "
                     "dropped before generation"),
        }
    except Exception as e:
        out["settings_error"] = str(e)
    return out


# ── A-17 ──────────────────────────────────────────────────────────────────
def corpus_composition():
    from src.config import settings as S
    d = Path(S.CORPUS_DIR)
    if not d.exists():
        return {"available": False, "note": f"{d} not found"}
    files = sorted(f for f in os.listdir(d) if f.endswith(".txt"))
    by = Counter()
    for f in files:
        m = re.match(r"([A-Za-z]+)", f)
        by[m.group(1).lower() if m else "other"] += 1
    sizes = Counter()
    for f in files:
        m = re.match(r"([A-Za-z]+)", f)
        sizes[m.group(1).lower() if m else "other"] += (d / f).stat().st_size
    return {"available": True, "corpus_dir": str(d), "n_files": len(files),
            "by_source": dict(by.most_common()),
            "bytes_by_source": {k: v for k, v in sizes.most_common()}}


# ── A-15 ──────────────────────────────────────────────────────────────────
def configuration():
    from src.config import settings as S
    out = {"python": sys.version.split()[0]}
    try:
        import importlib.metadata as md
        for pkg in ("sentence-transformers", "faiss-cpu", "faiss",
                    "llama-cpp-python", "numpy", "torch", "transformers"):
            try:
                out[pkg] = md.version(pkg)
            except Exception:
                pass
    except Exception:
        pass
    try:
        out["git_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT,
            stderr=subprocess.DEVNULL).decode().strip()
        out["git_branch"] = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT,
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        pass
    mp = getattr(S, "LLM_MODEL_PATH", "")
    if mp and os.path.exists(mp):
        out["llm_file"] = os.path.basename(mp)
        out["llm_bytes"] = os.path.getsize(mp)
    out["settings"] = {k: getattr(S, k) for k in
                       ("N_CTX", "TEMPERATURE", "TOP_K", "TOP_K_LLM",
                        "MAX_NEW_TOKENS", "CHUNK_SIZE", "CHUNK_OVERLAP",
                        "ANOMALY_THRESHOLD", "SEMANTIC_THRESHOLD",
                        "EMBEDDING_MODEL", "LLM_MODEL_PATH", "DATA_DIR")
                       if hasattr(S, k)}
    out["effective"] = {"b64_rule_mode": S.get_b64_rule_mode(),
                        "zwsp_mode": S.get_zwsp_mode(),
                        "l4_scope": S.get_l4_scope(),
                        "semantic_threshold": S.get_semantic_threshold(),
                        "anomaly_threshold": S.get_anomaly_threshold(),
                        "l3_operative_bar_normal": S.get_anomaly_threshold() * 2.0,
                        "l3_operative_bar_high": S.get_anomaly_threshold() * 0.7 * 2.0}
    return out


def main():
    res = {"A6b_attack_ratio": attack_ratio(),
           "A15_configuration": configuration(),
           "A16_truncation": truncation(),
           "A17_corpus_composition": corpus_composition()}
    save_json(res, "phase10", "offline_items.json")

    print("=" * 74)
    print("A-6(b)  expected latency at a realistic attack ratio")
    print("=" * 74)
    a = res["A6b_attack_ratio"]
    if a.get("available"):
        m = a["measured"]
        print(f"  measured: attack  baseline {m['attack_baseline_s']}s  "
              f"SecureRAG {m['attack_securerag_s']}s   (n={m['n_attacks']})")
        print(f"            legit   baseline {m['legit_baseline_s']}s  "
              f"SecureRAG {m['legit_securerag_s']}s   (n={m['n_legit']})")
        print(f"\n  {'attack %':>9}{'baseline':>11}{'SecureRAG':>12}{'overhead':>11}")
        for r in a["expected_latency"]:
            tag = "   <- thesis set" if r["attack_ratio"] == 0.75 else ""
            print(f"  {100*r['attack_ratio']:>8.0f}%{r['baseline_s']:>11}"
                  f"{r['securerag_s']:>12}{r['overhead_pct']:>10}%{tag}")
    else:
        print(" ", a.get("note"))

    print("\n" + "=" * 74)
    print("A-16  truncation")
    print("=" * 74)
    t = res["A16_truncation"]
    print(f"  embedder max_seq_length : {t.get('max_seq_length')}")
    print(f"  corpus chunk size       : {t.get('chunk_tokens')} tokens")
    if t.get("tokens_never_embedded_per_chunk"):
        print(f"  ** {t['tokens_never_embedded_per_chunk']} tokens per chunk are "
              f"never part of the vector **")
        print(f"     only {100*t['embedded_fraction_of_chunk']:.0f}% of each "
              f"chunk is embedded, so retrieval and L4 see that much")
    g = t.get("generation_budget", {})
    if g:
        print(f"  n_ctx {g['n_ctx']}  vs  top_k {g['top_k']} x {t.get('chunk_tokens')}"
              f" = {g['retrieved_tokens_max']} tokens of context"
              f" + ~{g['system_prompt_tokens_approx']} prompt"
              f" + {g.get('max_output_tokens')} output")
        ob = g.get("over_budget_by")
        if ob is not None:
            print(f"  total demand {g['total_demand']} tokens vs a "
                  f"{g['n_ctx']}-token window  -> "
                  + (f"OVER by {ob}" if ob > 0 else f"fits, {-ob} to spare"))
    if t.get("note"):
        print(" ", t["note"])

    print("\n" + "=" * 74)
    print("A-17  corpus composition")
    print("=" * 74)
    c = res["A17_corpus_composition"]
    if c.get("available"):
        print(f"  {c['n_files']} files in {c['corpus_dir']}")
        for k, v in c["by_source"].items():
            print(f"    {k:<20}{v:>6}")
    else:
        print(" ", c.get("note"))

    print("\n" + "=" * 74)
    print("A-15  configuration")
    print("=" * 74)
    cfg = res["A15_configuration"]
    for k, v in cfg.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for kk, vv in v.items():
                print(f"    {kk:<28}{vv}")
        else:
            print(f"  {k:<30}{v}")
    print("\n  saved -> Change-B4/phase10/offline_items.json")


if __name__ == "__main__":
    main()
