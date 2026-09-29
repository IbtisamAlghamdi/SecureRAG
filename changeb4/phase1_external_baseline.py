#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
changeb4/phase1_external_baseline.py  --  examiner item A-7
===========================================================
The thesis reports a DEFENDED external true-compliance ASR of 15.92% but never
ran the same 986 BIPIA attacks with the defenses off under the same compliance
classifier, so it cannot show the defense lowered actual compliance externally.

This runs exactly that: same eval_set.json, same pipeline, same scorer,
defenses disabled. Nothing existing is overwritten -- output lands in
Change-B4/phase1/ with a __baseline suffix.

Expected direction (stated in advance so the result can be checked against it):
the 566 attacks that already reach the model are handled identically either
way, and the 420 the defense blocks cannot comply while blocked, so undefended
compliance must be >= defended compliance. A result in the other direction
would indicate a bug, not a finding.

Cost: every one of the 986 queries reaches the model. ~5 h on an M4 Air.

Usage:  python3 changeb4/phase1_external_baseline.py --model Mistral-7B
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from changeb4.common import out_dir, save_json          # noqa: E402


def sh(cmd):
    print("\n$ " + " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        raise SystemExit(f"command failed with exit code {r.returncode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Mistral-7B")
    ap.add_argument("--limit", type=int, default=None,
                    help="smoke-test on the first N samples before the full run")
    ap.add_argument("--margin", type=float, default=0.05)
    args = ap.parse_args()

    d = out_dir("phase1")
    safe = args.model.replace("/", "_").replace(" ", "_")

    cmd = [sys.executable, "run_external_eval.py", "--model", args.model,
           "--no-defenses", "--out-dir", str(d)]
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    sh(cmd)

    results_csv = d / f"bipia_external_results__{safe}__baseline.csv"
    if not results_csv.exists():
        cands = sorted(d.glob("bipia_external_results__*__baseline.csv"))
        if not cands:
            raise SystemExit(f"expected results CSV not found in {d}")
        results_csv = cands[0]

    sh([sys.executable, "classify_true_compliance.py",
        "--results", str(results_csv),
        "--margin", str(args.margin),
        "--out", str(d / f"compliance_classified__{safe}__baseline.csv")])

    save_json({
        "item": "A-7",
        "what": "undefended baseline over the same 986 BIPIA attacks, scored "
                "with the same compliance classifier as the defended run",
        "model": args.model,
        "results_csv": str(results_csv.relative_to(ROOT)),
        "compliance_csv": str((d / f'compliance_classified__{safe}__baseline.csv')
                              .relative_to(ROOT)),
        "defended_reference_from_thesis": {
            "blocked_before_model": 420, "reached": 566,
            "complied": 157, "true_compliance_asr_pct": 15.92,
            "reach_rate_asr_pct": 57.40, "neutralised_pct": 84.08,
        },
        "next": "read the 'Estimated TRUE ASR' line printed by "
                "classify_true_compliance.py above; that is the undefended "
                "figure to place beside 15.92%.",
    }, "phase1", "A7_summary.json")
    print("\nPhase 1 complete.")


if __name__ == "__main__":
    main()
