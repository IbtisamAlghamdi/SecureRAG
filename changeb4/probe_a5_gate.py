#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/probe_a5_gate.py  --  ten-minute reconnaissance for examiner item A-5
==============================================================================
A-5 asks for knowledge-base poisoning (PoisonedRAG-style): the injected
instruction sits inside a RETRIEVED DOCUMENT, and the user's query is clean.

L0-L3 all read the QUERY. On a clean query they have nothing to look at, so
the only layer that could intervene is L4 -- and L4 is gated in
src/pipeline.py on `risk in (HIGH, MEDIUM) or anomaly_score > 0`.

This probe answers, offline and in seconds, the question that decides whether
the full A-5 build is worth half a day:

    on a clean, legitimate query, does the L4 gate open at all?

If it never opens, the corpus-poisoning result is knowable in advance: the
framework performs no check whatsoever, and the honest write-up is a scoped
threat-model boundary plus the always-on-L4 variant, not a surprise.

No model, no generation, no index. Usage:
    python3 changeb4/probe_a5_gate.py
"""
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import run_input_layers, make_batch, save_json  # noqa: E402

REAL_FILES = ["beir_nq_queries.txt", "beir_scifact_queries.txt",
              "beir_fiqa_queries.txt"]


def collect():
    """Real third-party queries first; the generated benign set as a fallback."""
    out = []
    for name in REAL_FILES:
        p = ROOT / name
        if not p.exists():
            for cand in ROOT.rglob(name):
                p = cand
                break
        if p.exists():
            qs = [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
            out += [(name, q) for q in qs[:100]]
    _, benign = make_batch(42)
    out += [("generated_benign", q) for q in benign[:100]]
    return out


def main():
    queries = collect()
    if not queries:
        print("no benign queries found -- nothing to probe")
        return

    rows, gate_open, blocked = [], 0, 0
    risks, anomalies = Counter(), []
    for source, q in queries:
        r = run_input_layers(q)
        if r["blocked_at"]:
            blocked += 1
        open_ = bool(r["l4_gate_open"])
        gate_open += open_
        risks[r["risk"]] += 1
        if r["anomaly_score"] is not None:
            anomalies.append(r["anomaly_score"])
        rows.append({"source": source, "query": q[:120],
                     "blocked_at": r["blocked_at"] or "",
                     "risk": r["risk"],
                     "anomaly_score": r["anomaly_score"],
                     "l4_gate_open": open_})

    n = len(rows)
    nz = sum(1 for a in anomalies if a and a > 0)
    print("=" * 74)
    print("A-5 reconnaissance -- does L4 ever run on a clean query?")
    print("=" * 74)
    print(f"  clean queries probed            {n}")
    print(f"  blocked by L1/L2/L3             {blocked}  ({100*blocked/n:.1f}%)")
    print(f"  risk distribution               {dict(risks)}")
    print(f"  non-zero anomaly score          {nz}  ({100*nz/n:.1f}%)")
    print(f"  L4 GATE OPEN                    {gate_open}  ({100*gate_open/n:.1f}%)")
    print()
    if gate_open == 0:
        print("  VERDICT: the gate never opens on a clean query.")
        print("  A poisoned document reached through a clean query is examined")
        print("  by NO layer. The A-5 number is therefore the undefended number,")
        print("  and no build is needed to predict it -- only to quantify it.")
        print("  Report as a threat-model boundary; measure the always-on-L4")
        print("  variant as the proposed remedy (its FPR cost is already known:")
        print("  1/999 = 0.10% from phase 5).")
    else:
        print(f"  VERDICT: the gate opens on {100*gate_open/n:.1f}% of clean queries,")
        print("  so L4 would inspect that share of poisoned-document answers.")
        print("  The full A-5 build is worth running: the outcome is not")
        print("  determined in advance.")
    print()

    save_json({"n": n, "blocked_by_input_layers": blocked,
               "risk_distribution": dict(risks),
               "nonzero_anomaly": nz, "l4_gate_open": gate_open,
               "l4_gate_open_pct": round(100 * gate_open / n, 2),
               "rows": rows},
              "probe_a5", "A5_gate_probe.json")
    print("  saved -> Change-B4/probe_a5/A5_gate_probe.json")


if __name__ == "__main__":
    main()
