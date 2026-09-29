#!/usr/bin/env bash
# =====================================================================
#  SecureRAG -- final evaluation run
#
#  One configuration for every number in the thesis. Each stage writes its
#  own output the moment it finishes and drops a marker file; re-running
#  this script skips whatever already succeeded and carries on from there.
#  A stage that fails is recorded and the run continues, so one failure
#  never costs the stages after it.
#
#  Usage:   bash run_final.sh
#  Resume:  bash run_final.sh          (same command; finished stages skip)
#  Redo a stage:  rm Change-B4/_done/<stage>.done   then run again
# =====================================================================
set -u
set -o pipefail

# ---- the one configuration -------------------------------------------
export SECURERAG_L4_SCOPE=retrieved
export SECURERAG_SEMANTIC_THRESHOLD=0.1495
export SECURERAG_B64_RULE_MODE=decode
export SECURERAG_ZWSP_MODE=space
export SECURERAG_CHUNK_SCAN=off

SEEDS="839 941 1049 1151 1279"
SEED_T0="839"

DONE="Change-B4/_done"
LOGS="Change-B4/_logs"
mkdir -p "$DONE" "$LOGS"
RUNLOG="$LOGS/run_final_$(date +%Y%m%d_%H%M%S).log"

say()  { echo "" | tee -a "$RUNLOG"; echo "$*" | tee -a "$RUNLOG"; }
stamp(){ date "+%Y-%m-%d %H:%M:%S"; }

FAILED=""

stage() {
  local key="$1"; shift
  local desc="$1"; shift
  if [ -f "$DONE/$key.done" ]; then
    say "[skip] $key -- $desc (already finished)"
    return 0
  fi
  say "[start $(stamp)] $key -- $desc"
  local lg="$LOGS/$key.log"
  if ( set -x; "$@" ) >"$lg" 2>&1; then
    date "+%Y-%m-%d %H:%M:%S" > "$DONE/$key.done"
    say "[done  $(stamp)] $key   log: $lg"
  else
    FAILED="$FAILED $key"
    say "[FAIL  $(stamp)] $key   log: $lg   -- continuing"
    tail -15 "$lg" | sed 's/^/        /' | tee -a "$RUNLOG"
  fi
}

# =====================================================================
say "=============================================================="
say " SecureRAG final run -- started $(stamp)"
say "=============================================================="
say " L4_SCOPE=$SECURERAG_L4_SCOPE  SEMANTIC_THRESHOLD=$SECURERAG_SEMANTIC_THRESHOLD"
say " B64_RULE_MODE=$SECURERAG_B64_RULE_MODE  ZWSP_MODE=$SECURERAG_ZWSP_MODE"
say " CHUNK_SCAN=$SECURERAG_CHUNK_SCAN"
say " seeds: $SEEDS   temperature-0 seed: $SEED_T0"

# ---- stage 0: preflight ---------------------------------------------
say ""
say "---- preflight ----"
PFFAIL="$LOGS/.preflight_failures"
: > "$PFFAIL"
need_file() { if [ -e "$1" ]; then echo "  ok    $1"; else echo "  MISS  $1"; echo "$1" >> "$PFFAIL"; fi; }

{
  echo "python: $(python3 -V 2>&1)"
  for s in changeb4/phase5_full_pipeline_seeds.py \
           changeb4/phase11_ablation_offline.py \
           changeb4/phase12_truncation_evasion.py \
           changeb4/phase13_classifier_arm.py \
           run_external_eval.py classify_true_compliance.py model_select.py; do
    need_file "$s"
  done
  need_file "eval_set.json"
  python3 - "$PFFAIL" <<'PY'
import sys, os
fail = open(sys.argv[1], "a")
sys.path.insert(0, os.getcwd())
try:
    from src.config import settings
except Exception as e:
    print("  MISS  settings import:", e); fail.write("settings\n"); raise SystemExit(0)
print("  ok    settings import")
for k, fn in [("temperature","get_temperature"),("l4 scope","get_l4_scope"),
              ("semantic thr","get_semantic_threshold"),("b64 mode","get_b64_rule_mode"),
              ("zwsp mode","get_zwsp_mode"),("chunk scan","get_chunk_scan")]:
    f = getattr(settings, fn, None)
    if f: print(f"  ok     {k:14s} = {f()}")
    else: print(f"  MISS   {k:14s} getter missing"); fail.write(fn+"\n")
import os.path as op
for name in ("Mistral-7B", "Llama-3.2-3B"):     # the only two this run loads
    cfg = settings.MODELS_CONFIG.get(name)
    if not cfg:
        print(f"  MISS  model {name} not in MODELS_CONFIG"); fail.write(name+"\n"); continue
    p = op.join(settings.MODELS_DIR, cfg["file"])
    if op.exists(p): print(f"  ok    model {name}")
    else: print(f"  MISS  model {name}: {p}"); fail.write(p+"\n")
fail.close()
PY
  echo "disk free: $(df -h . | tail -1 | awk '{print $4}')"
} 2>&1 | tee -a "$RUNLOG"

if [ -s "$PFFAIL" ]; then
  say "PREFLIGHT FAILED -- missing:"
  sed 's/^/    /' "$PFFAIL" | tee -a "$RUNLOG"
  say "Nothing was run."
  exit 1
fi

# a real two-query pass, so a broken pipeline fails here and not in hour four
stage preflight_smoke "two-query end-to-end smoke" \
  python3 -u changeb4/phase5_full_pipeline_seeds.py --model Mistral-7B --seeds 839 --limit 2
if [ ! -f "$DONE/preflight_smoke.done" ]; then
  say "SMOKE FAILED -- the pipeline does not run. Stopping before the long stages."
  exit 1
fi

# ---- the cheap stages first -----------------------------------------
stage a12_ablation "A-12 ablation, all seeds, cumulative + leave-one-out" \
  python3 -u changeb4/phase11_ablation_offline.py --seeds $SEEDS

stage a16_truncation "A-16 embedding truncation and the retrieval blind spot" \
  python3 -u changeb4/phase12_truncation_evasion.py

stage a14_classifier "A-14 open-source classifier arm" \
  python3 -u changeb4/phase13_classifier_arm.py --seeds $SEEDS

# ---- the generation stages ------------------------------------------
stage internal_main "internal full pipeline, 5 seeds, temperature 0.7" \
  python3 -u changeb4/phase5_full_pipeline_seeds.py --model Mistral-7B --seeds $SEEDS

stage internal_temp0 "A-19 internal, one seed, temperature 0" \
  env SECURERAG_TEMPERATURE=0 python3 -u changeb4/phase5_full_pipeline_seeds.py \
      --model Mistral-7B --seeds $SEED_T0

stage cross_model "cross-model, Llama-3.2-3B, same seeds" \
  python3 -u changeb4/phase5_full_pipeline_seeds.py --model Llama-3.2-3B --seeds $SEEDS

# ---- the external stage ---------------------------------------------
BIPIA_OUT="Change-B4/phase1_defended_final"
stage bipia_defended "BIPIA defended, 986 attacks, new L4 configuration" \
  python3 -u run_external_eval.py --model Mistral-7B --out-dir "$BIPIA_OUT"

if [ -f "$DONE/bipia_defended.done" ]; then
  BIPIA_CSV="$(ls "$BIPIA_OUT"/bipia_external_results*.csv 2>/dev/null | head -1)"
  if [ -n "${BIPIA_CSV:-}" ]; then
    stage bipia_compliance "BIPIA true-compliance classification" \
      python3 -u classify_true_compliance.py \
        --results "$BIPIA_CSV" --margin 0.05 \
        --out "$BIPIA_OUT/compliance_classified.csv"
  else
    say "[FAIL] bipia_compliance -- no results CSV found under $BIPIA_OUT"
    FAILED="$FAILED bipia_compliance"
  fi
fi

# =====================================================================
say ""
say "=============================================================="
say " finished $(stamp)"
if [ -n "$FAILED" ]; then
  say " STAGES THAT FAILED:$FAILED"
  say " their logs are under $LOGS/ ; fix and re-run this same script --"
  say " everything that succeeded is skipped."
else
  say " every stage completed."
fi
say " outputs under Change-B4/ ; run log: $RUNLOG"
say "=============================================================="
