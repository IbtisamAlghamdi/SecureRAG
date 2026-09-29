#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/run_all.py  --  one command, one night
===============================================
Runs the Change-B4 phases in order, skipping any phase whose output already
exists, so an interrupted run resumes instead of starting over.

    python3 changeb4/run_all.py --model Mistral-7B            # everything
    python3 changeb4/run_all.py --preflight                   # checks only
    python3 changeb4/run_all.py --only 0                      # one phase
    python3 changeb4/run_all.py --smoke                       # tiny sizes

Nothing outside Change-B4/ is written. No existing result file is touched.
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import OUT_ROOT  # noqa: E402

PHASES = [
    (0, "offline  (A-3, A-12, A-21, A-22, A-23)", "phase0/phase0_results.json",
     ["changeb4/phase0_offline.py"], "~3 min"),
    ("0b", "circularity: held-out templates + third-party sets (A-2)",
     "phase0b/A2_results.json", ["changeb4/phase0b_heldout_and_public.py"], "~4 min"),
    ("0c", "base64 shape rule: measure and fix (A-21)",
     "phase0c/A21_b64_rule_results.json", ["changeb4/phase0c_b64_rule.py"], "~3 min"),
    ("0d", "audit of the fixes (anti-circularity checks)",
     "phase0d/audit_results.json", ["changeb4/phase0d_audit.py"], "~2 min"),
    (1, "external undefended baseline (A-7)", "phase1/A7_summary.json",
     ["changeb4/phase1_external_baseline.py"], "~5 h"),
    (2, "internal compliance + canary (A-1, A-8, A-9)", "phase2/A1_summary.json",
     ["changeb4/phase2_internal_compliance.py"], "~1.5 h"),
    (3, "real benign queries + latency (A-20, A-6)", "phase3/A20_A6_summary.json",
     ["changeb4/phase3_real_benign.py"], "~1.5 h"),
    (5, "full pipeline on held-out seeds (A-3, A-12, A-10)",
     "phase5/A3_A12_A10_summary.json",
     ["changeb4/phase5_full_pipeline_seeds.py"], "~1.5 h"),
    (4, "analysis (A-9 ROC, A-8 kappa, A-10)", "phase4/phase4_analysis.json",
     ["changeb4/phase4_analysis.py"], "~1 min"),
]


def preflight(model):
    print("preflight")
    ok = True

    def chk(label, cond, hint=""):
        nonlocal ok
        print(f"  [{'ok' if cond else 'MISSING'}] {label}" + ("" if cond else f"   -> {hint}"))
        ok = ok and cond

    try:
        from src.config import settings
        from model_select import model_path_for
        mp = Path(model_path_for(model))
        chk(f"GGUF model  ({mp.name})", mp.exists(), "run download_models.py")
    except Exception as e:
        chk(f"model lookup for '{model}'", False, str(e))
    for mod in ("faiss", "llama_cpp", "sentence_transformers"):
        try:
            __import__(mod)
            chk(f"python module {mod}", True)
        except Exception:
            chk(f"python module {mod}", False, "activate the RAG environment")
    chk("eval_set.json (BIPIA)", (ROOT / "eval_set.json").exists(),
        "run build_eval_set.py")
    corpus = ROOT / "data" / "corpus"
    n = len(list(corpus.glob("*"))) if corpus.exists() else 0
    chk(f"corpus documents ({n} files)", n > 0, "run download_datasets.py")
    beir = list((ROOT / "data").glob("beir_*_queries.txt")) if (ROOT / "data").exists() else []
    chk(f"real query files ({len(beir)} found)", len(beir) > 0,
        "run download_datasets.py  (phase 3 A-20 needs these)")
    print("  ->", "ready" if ok else "fix the items above first")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Mistral-7B")
    ap.add_argument("--only", default=None,
                    help="0, 0b, 1, 2, 3 or 4")
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--smoke", action="store_true",
                    help="tiny sample sizes -- proves the plumbing in minutes")
    ap.add_argument("--force", action="store_true", help="re-run completed phases")
    args = ap.parse_args()

    if args.preflight:
        sys.exit(0 if preflight(args.model) else 1)
    if not preflight(args.model):
        print("\nAborting: preflight failed. Use --only 0 to run the offline "
              "phase anyway (it needs none of the above).")
        if args.only != 0:
            sys.exit(1)

    t_start = time.time()
    for num, label, marker, cmd, cost in PHASES:
        if args.only is not None and str(num) != str(args.only):
            continue
        done = (OUT_ROOT / marker).exists()
        print("\n" + "=" * 74)
        print(f"PHASE {num}  {label}   [{cost}]")
        print("=" * 74)
        if done and not args.force:
            print(f"  already complete ({marker}) -- skipping (use --force to redo)")
            continue
        full = [sys.executable, "-u"] + cmd
        if num in (1, 2, 3, 5, "0b"):
            full += ["--model", args.model]
        if args.smoke:
            if num == "0b":
                full += ["--n-per-half", "120"]
            if num == 1:
                full += ["--limit", "12"]
            if num == 2:
                full += ["--n", "8"]
            if num == 3:
                full += ["--n-full", "8"]
            if num == 5:
                full += ["--limit", "40", "--seeds", "42"]
        t0 = time.time()
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        r = subprocess.run(full, cwd=ROOT, env=env)
        if r.returncode != 0:
            print(f"\nPHASE {num} FAILED (exit {r.returncode}). "
                  f"Everything completed so far is kept; re-run the same "
                  f"command to resume from here.")
            sys.exit(r.returncode)
        print(f"  phase {num} done in {(time.time()-t0)/60:.1f} min")

    print("\n" + "=" * 74)
    print(f"ALL REQUESTED PHASES COMPLETE in {(time.time()-t_start)/60:.1f} min")
    print(f"Everything is under: {OUT_ROOT}")
    print("=" * 74)


if __name__ == "__main__":
    main()
