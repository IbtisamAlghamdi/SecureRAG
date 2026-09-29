# Measurement outputs behind Chapter 4

Each file is the summary written by the script of the same phase in
`evidence/changeb4/`. Figures in the thesis are read from these files.

| Chapter 4 item | File |
|---|---|
| Table 4.3, 4.5 (L4 row), §4.5.1, §4.5.2 | `phase5/A3_A12_A10_summary__Mistral-7B.json` |
| Tables 4.16–4.18, cross-model | `phase5/A3_A12_A10_summary__Llama-3.2-3B.json` |
| §4.5.3, manual compliance labels | `phase2/A1_summary.json`, `phase2/A8_manual_labelling_sheet.csv` |
| Table 4.4, latency; 300 real queries | `phase3/A20_A6_summary.json` |
| Table 4.5 (nine rule tiers), Tables 4.9, 4.10 | `phase14/A29_variant_tier_summary.json` |
| Table 4.6, Table 4.8 ablation | `phase11/A12_ablation_summary.json` |
| Table 4.7, output-guardrail ROC | `phase8/A9_l4_comparison.json` |
| Semantic threshold 0.1495; recall 19.81 % and 36.79 % | `phase9/L4_threshold_calibration.json` |
| Table 4.12, undefended arm | `phase1/bipia_external_summary__Mistral-7B__baseline.json`, `phase1/A7_summary.json` |
| Table 4.12, defended arm (deployed) | `phase1_defended_final/bipia_external_summary__Mistral-7B.json` |
| Table 4.13, left column (threshold 0.18) | `phase1_defended/bipia_external_summary__Mistral-7B.json` |
| Table 4.15, knowledge-base poisoning | `phase7/A5_summary.json`, `phase7/A5_kb_poisoning_rows.csv` |
| Poisoning repeat, payload at end of document | `phase7/A5_summary__tail.json` |
| Poisoning retrieval control | `phase7/A5_retrieval_condition.json` |
| Table 4.19, reference defenses | `phase6/A14_summary.json` |
| Tables 4.20, 4.21, trained classifier | `phase13/A14_classifier_arm_summary.json` |
| Table 4.23 left column, table as evaluated | `phase15/A30_adaptive_summary__as_evaluated.json` |
| Table 4.23 right column, four entries added | `phase15/A30_adaptive_summary__complete_map.json` |
| Embedding-window truncation, §4.6 | `phase12/A16_truncation_summary.json` |
| Sanitizer switch matrix (Appendix) | `phase0d/switch_matrix.csv` |
| Section 5.5 and the appendix: the completed look-alike table | `patched_table/` |

## Seed sets

Two disjoint sets are used and must not be compared directly.

- **Calibration seeds** 42, 137, 271, 413, 509 — the switch matrix, the L3
  threshold sweep, and the L4 threshold calibration.
- **Evaluation seeds** 839, 941, 1049, 1151, 1279 — every figure reported as
  a result: phase5, phase11, phase13, phase14, phase15.

The switch matrix therefore reports 89.15 % for the deployed combination
while Chapter 4 reports 89.35 % for the four input layers. The two are
measured on different, disjoint seed sets; they are not the same quantity.

## A note on two stale fields

`phase8/A9_l4_comparison.json` and `phase9/L4_threshold_calibration.json`
each carry `"deployed_threshold": 0.18`. That field records the default in
`src/config/settings.py`. The deployed value is 0.1495 and is supplied at
run time through `SECURERAG_SEMANTIC_THRESHOLD`, as
`evidence/measurements/phase1_defended_final/` records. The same applies to
`semantic_threshold` in the Llama external false-positive summary.

## External runs by configuration

`evidence/` holds the deployed configuration for Mistral-7B. The earlier
configuration — output check against the whole index at threshold 0.18 —
is kept under `evidence/archive_experimental_runs/` with the suffix
`__thr018_corpus`. No external attack run under the deployed configuration
exists for Llama-3.2-3B; Chapter 4 reports no external figure for that
model.

## Two states of the look-alike table

Chapter 4 reports the state whose manifest digest is `d6744aea...`, in which
`UNICODE_LOOKALIKE_MAP` folds four of the eight Latin letters the generator
substitutes. Its measurements are `phase11/` and `phase14/`:

    L1 826, L2 3,523, L3 123     detection 89.35 %   homoglyph 72.24 %

Adding the four remaining Cyrillic codepoints, as
`PROPOSED_homoglyph_map_completion.patch` sets out, gives the figures
Section 5.5 quotes. Those runs are kept separately under `patched_table/`
so that neither state can be read for the other:

    L1 835, L2 3,587, L3 116     detection 90.67 %   homoglyph 88.45 %

The adaptive attacker reaches both states without editing the sanitizer:
its `--complete-map` flag folds the attacker's own substitutions back
before inspection.

## Reproducing a measurement

The deployed configuration is supplied through the environment, not through
`src/config/settings.py`, whose defaults differ. A run started without it
silently measures the wrong configuration:

    export SECURERAG_B64_RULE_MODE=decode
    export SECURERAG_ZWSP_MODE=space
    export SECURERAG_L4_SCOPE=retrieved
    export SECURERAG_SEMANTIC_THRESHOLD=0.1495

    python3 changeb4/phase15_adaptive_attacker.py --seeds 839 941 1049 1151 1279
    python3 changeb4/phase15_adaptive_attacker.py --seeds 839 941 1049 1151 1279 --complete-map

Under the file defaults the same two commands return 62.5 % rather than
69.20 %, because `shape` blocks every Base64 segment on sight.
