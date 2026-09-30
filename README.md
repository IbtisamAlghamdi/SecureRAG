# SecureRAG

A five-layer, training-free defense framework that protects Retrieval-Augmented
Generation systems against prompt injection. It runs entirely on locally deployed
open-weight models, with no dependency on external APIs.

This repository holds the implementation and the evaluation code for the master's
thesis *Layered Defense Against Prompt Injection in Enterprise
Retrieval-Augmented Generation Systems: Design, Implementation, and Evaluation*.

---

## How the defense works

A query passes through five layers in order and stops at the first one that blocks it.

| Layer | Name | What it does |
|---|---|---|
| **L0** | Adaptive Risk Sensor | Classifies the query LOW, MEDIUM or HIGH. It does not block; the classification lowers L3's bar for high-risk queries and opens L4's gate. |
| **L1** | Input Sanitization | Reverses obfuscation: Unicode homoglyphs, zero-width characters, Base64 payloads, template injection. |
| **L2** | Rule-Based Filter | Matches the sanitized query against nine named pattern tiers. |
| **L3** | Anomaly Detection | Scores the query across five of six statistical dimensions together with a group of framing patterns, and blocks structurally anomalous input. |
| **L4** | Semantic Guardrail | After generation, compares the response against the knowledge base and suppresses answers that have drifted outside it. |

L0 through L3 read only the query text, so their decisions are independent of which
language model is loaded. L4 is the only layer that inspects the model's output.

---

## Results

Mistral-7B-Instruct v0.2. Five evaluation seeds — **839, 941, 1049, 1151, 1279** —
none of which was used to set any threshold. 1,001 attacks and 333 legitimate
queries per run, pooling to **5,005 attacks and 1,665 legitimate queries**.

| | Result |
|---|---|
| Attack bypass rate | **9.99 %** [9.19, 10.85] — 500 of 5,005 (undefended baseline: 100 %) |
| Detection rate | **90.01 %** — 4,505 attacks blocked |
| Input layers alone (L0–L3) | 10.65 % [9.82, 11.53] |
| False positive rate | **0.00 %** [0.00, 0.23] over 1,665 legitimate queries |
| Latency, attacks | 1.73 s mean over every attack query |
| Latency, answered in full | 16.83 s defended against 16.92 s undefended, on 150 real queries (−0.55 %) |

Intervals are 95 % Wilson intervals on the pooled counts.

**Blocks by layer**, pooled: L1 826 · L2 3,523 · L3 123 · L4 33.

**Calibration** used a separate set of seeds, kept apart from the five above:
42, 137, 271, 413 and 509 for the anomaly threshold; 137 and 271 for the output guardrail.

### External benchmark — BIPIA

986 attacks, both the defended and the undefended pipeline run in this codebase and
scored by the same measure, so the comparison is controlled rather than cross-paper.

| | Undefended | SecureRAG |
|---|---|---|
| Blocked before generation | 0 | 566 (57.40 %) |
| Complied | **98 (9.94 %)** [8.22, 11.96] | **55 (5.58 %)** [4.31, 7.19] |

Intervals are disjoint. McNemar on the paired outcomes: b = 79, c = 36,
χ² = 15.34, p < 0.001. External false positives under the deployed configuration
are 20 of 333 documents (6.01 %), all of them on tabular material and none on any
query written by a user.

### Cross-model — Llama-3.2-3B-Instruct

The four input layers return an **identical bypass rate of 10.65 %, seed by seed**,
on both models: their decisions read only the query text. The output guardrail does
not transfer — on Llama it adds 170 blocks but costs 3.18 % [2.44, 4.14] false
positives against 0.00 % on Mistral, so its threshold has to be recalibrated per
model.

### Deployed configuration

The reported results were produced with these settings, which are read through
environment variables and override the file defaults:

```bash
SECURERAG_SEMANTIC_THRESHOLD=0.1495   # output guardrail
SECURERAG_L4_SCOPE=retrieved          # compare against the retrieved passages
SECURERAG_B64_RULE_MODE=decode        # decode Base64 and inspect
SECURERAG_ZWSP_MODE=space             # replace zero-width characters
```

`ANOMALY_THRESHOLD` is 15.0, with L3 blocking at 30.0 and at 21.0 for queries L0
marked HIGH risk.

[`FINAL_RESULTS.md`](FINAL_RESULTS.md) records an earlier run on the calibration
seeds (42, 137, 271, 413, 509) and is kept for the audit trail. It is **not** the
run reported in the thesis; the numbers above are.

---

## Project structure

```
SecureRAG/
├── src/
│   ├── pipeline.py                     the five-layer pipeline; L0 lives here    (389)
│   ├── config/
│   │   └── settings.py                 all thresholds and model paths            (273)
│   ├── defenses/
│   │   ├── sanitization/sanitize.py    L1  input sanitization                    (318)
│   │   ├── rules/rule_filter.py        L2  nine rule tiers                       (606)
│   │   ├── anomaly/anomaly_detector.py L3  six-dimension anomaly score           (336)
│   │   └── semantic/semantic_detector.py L4 output guardrail                     (127)
│   ├── attacks/
│   │   └── generator.py                attack and benign generators              (841)
│   └── rag_core/
│       ├── embeddings/embedder.py      Sentence-BERT                              (64)
│       ├── retrieval/faiss_engine.py   FAISS index                               (112)
│       └── generation/llm_engine.py    GGUF model loader                          (99)
│
├── thesis_evaluation.py                five-seed internal evaluation             (768)
├── model_select.py                     the single point where the model is chosen
├── chat.py                             interactive console
│
├── build_eval_set.py                   builds the BIPIA attack set
├── run_external_eval.py                runs the external attack evaluation
├── classify_true_compliance.py         separates "reached the model" from "complied"
├── measure_layer_effectiveness.py      per-query tally of which layer blocked what
│
├── run_external_fpr_eval.py            external false-positive run
├── build_fresh_holdout_fpr.py          never-tuned holdout sample
├── check_real_query_fpr.py             real human-written queries
├── diagnose_fpr.py                     internal false-positive run
│
├── threshold_sensitivity_analysis.py   sweep of L4's semantic threshold
├── l3_threshold_sensitivity.py         sweep of L3's anomaly threshold
├── generate_final_charts.py            all thesis figures
├── run_demo_appendix.py                the qualitative demonstration
├── verify_no_model.py                  generator integrity checks, no model needed
├── run_final.sh                        runs every stage above in order, and resumes
│
├── download_models.py                  fetches the GGUF models
├── download_datasets.py                fetches BEIR and Wikipedia
└── download_enron.py                   fetches the Enron email sample
```

Result files (`bipia_external_*.csv`, `eval_set.json`, `fpr_set.json`,
`benign_fpr_diagnosis.csv`, `l3_threshold_sensitivity.json`) are the outputs of the
runs reported in the thesis and are kept so every figure can be traced back to data.

---

## Getting started

Full instructions, including the corpus build, are in [`SETUP.md`](SETUP.md).

```bash
conda create -n RAG python=3.11 && conda activate RAG
pip install -r requirements.txt

python3 download_models.py        # GGUF models
python3 download_datasets.py      # corpus

python3 chat.py                                    # try it interactively
python3 thesis_evaluation.py --model Mistral-7B    # reproduce the main results
```

Two checks run without loading a language model, so they are the quickest way to
confirm the installation:

```bash
python3 verify_no_model.py             # generator integrity
python3 l3_threshold_sensitivity.py    # the L3 threshold sweep
```

---

## Reproducing the results

Every figure and table in Chapter 4 is produced by the scripts below. Run them in
this order; each writes its own result file, and the numbers to expect are stated
so a run can be checked rather than trusted.

### Before anything

Install and fetch the models and corpus as in **Getting started** above, then set
the reported configuration. It is not the file default, and every
threshold-dependent number will differ without it:

```bash
export SECURERAG_SEMANTIC_THRESHOLD=0.1495
export SECURERAG_L4_SCOPE=retrieved
export SECURERAG_B64_RULE_MODE=decode
export SECURERAG_ZWSP_MODE=space
```

If `export` does not reach the process under your shell, prefix each command with
`env VAR=value ...` instead.

### Two checks that need no model

They take seconds and confirm the installation before anything long starts.

```bash
python3 verify_no_model.py             # generator integrity
python3 l3_threshold_sensitivity.py    # the L3 sweep of Appendix C
```

The sweep should place detection at 89.37 % and the internal false positive rate at
0.00 % when the anomaly threshold is 15.0.

### 1 — The internal evaluation

```bash
python3 changeb4/phase5_full_pipeline_seeds.py --model Mistral-7B
```

Five seeds — 839, 941, 1049, 1151, 1279 — 1,001 attacks and 333 legitimate queries
each. Expect:

| | Expected |
|---|---|
| Attack bypass rate, pooled | 9.99 % — 500 of 5,005 |
| Input layers alone (L0–L3) | 10.65 % — 533 of 5,005 |
| False positive rate | 0.00 % — 0 of 1,665 |
| Blocks by layer | L1 826 · L2 3,523 · L3 123 · L4 33 |
| Per-seed bypass, L0–L3 | 11.39 · 10.69 · 10.69 · 9.59 · 10.89 |

L0 through L3 read only the query text, so their counts are deterministic and
should reproduce exactly. L4 inspects generated text at temperature 0.7, so the
33 it adds may vary by a few; at temperature 0 the pooled bypass moves by 0.20
points, which is inside the 0.38-point spread between seeds.

### 2 — The ablation

```bash
python3 changeb4/phase11_ablation_offline.py
```

No language model is loaded. Seven configurations, false positive rate 0.00 % in
all seven. Expect bypass of 100.00 % for L0 alone, 83.50 % for L0–L1, 13.11 % for
L0–L2, 10.65 % for L0–L3; and, removing one layer at a time from the complete
framework, +47.81 points without L2, +2.48 without L1, +2.46 without L3.

### 3 — Per-variant and per-tier counts

```bash
python3 changeb4/phase14_variants_and_tiers.py
```

Base64 96.73 %, zero-width 95.79 %, context-wrapped 91.95 %, plain 88.95 %,
homoglyph 72.24 %. Of the nine L2 tiers, `direct_injection` accounts for 1,379 of
the 3,523 rule blocks and `output_hijack` for none.

### 4 — The external benchmark

```bash
python3 build_eval_set.py
python3 run_external_eval.py --model Mistral-7B          # defended arm
python3 changeb4/phase1_external_baseline.py             # undefended arm
python3 classify_true_compliance.py
python3 run_external_fpr_eval.py --model Mistral-7B
```

986 attacks on both arms. Compliance falls from 98 (9.94 %) to 55 (5.58 %), with
95 % Wilson intervals of [8.22, 11.96] and [4.31, 7.19] — disjoint. McNemar on the
paired outcomes gives b = 79, c = 36, χ² = 15.34. The external false positive run
returns 20 of 333 documents (6.01 %), all of them tabular.

### 5 — Real queries and the paired latency

```bash
python3 changeb4/phase3_real_benign.py
```

300 human-written queries, none blocked. On the 150 answered in full, 16.83 s
defended against 16.92 s undefended — a difference of −0.55 %.

### 6 — Compliance on internal attacks

```bash
python3 changeb4/phase2_internal_compliance.py
```

200 attacks, 176 blocked before generation, 24 responses delivered. Of the 23
labelled by hand, one complied and one disclosed the prompt marker.

### 7 — The second model

```bash
python3 changeb4/phase5_full_pipeline_seeds.py --model Llama-3.2-3B
```

The four input layers must return 10.65 % again, seed for seed. The output
guardrail will not: on Llama it adds 170 blocks and 3.18 % false positives, which
is why its threshold is model-specific.

### 8 — Reference defenses and the trained classifier

```bash
python3 changeb4/phase6_reference_defenses.py
python3 changeb4/phase13_classifier_arm.py
```

### 9 — Knowledge-base poisoning

```bash
python3 changeb4/phase7_kb_poisoning.py
```

150 questions against a poisoned index. Disclosure of the system prompt falls from
10.94 % undefended to 0.00 %; the input layers contribute nothing, because the
query itself is innocent.

### 10 — Figures and the qualitative demonstration

```bash
python3 generate_final_charts.py
python3 run_demo_appendix.py --model Mistral-7B
```

### What lands where

| Path | Holds |
|---|---|
| `Change-B4/phase*/` | the per-phase result files of each step above |
| `evidence/` | the deployed-configuration run: the external benchmark on both arms, the compliance verdicts, the code manifest, and `measurements/` mapping every table in Chapter 4 to the file it is read from |
| `evidence/archive_experimental_runs/` | the earlier external configuration (threshold 0.18, whole-index scope), suffixed `__thr018_corpus`, kept for the audit trail |
| `results/` | the remaining per-model artefacts: the Llama external run, the external false-positive runs, per-layer tallies, the holdout sets |
| `eval_set.json`, `fpr_set.json` | the attack and legitimate sets as generated |
| `evidence/CODE_FINGERPRINT.txt` | the manifest of the code state all of this was run on |

### If a number does not reproduce

Check the four environment variables first: three of the five defense decisions and
the guardrail threshold are read through them, and the file defaults are different
on purpose, so that both sides of each choice can be measured from one code state.
Check next that the seeds are the five evaluation seeds and not the calibration
seeds. Anything that still differs after that, and that concerns L0 through L3, is
a real difference rather than sampling: those layers never see generated text.

---

## Reproducibility

Every result reported in the thesis comes from a single frozen state of the defense
code: no module under `src/defenses/` and no line of `src/pipeline.py` changed
between the first evaluation run and the last. The evaluation scripts outside `src/`
were extended during that period; the defense itself was not.

That state is identified by [`evidence/CODE_FINGERPRINT.txt`](evidence/CODE_FINGERPRINT.txt),
which lists the SHA-256 digest of each of the twenty-two source files under `src/`
and carries its own digest on its final line:

```
d6744aea2e56c4cb0d889a3cce64b35deb28385cdd20b52519934d8963d465aa
```

To check a clone against it:

```bash
sed '$d' evidence/CODE_FINGERPRINT.txt | shasum -a 256
```

The value printed must be the one above. Any change to any of the twenty-two files,
however small, changes the manifest and therefore changes that value. The manifest
covers the defense implementation and the generators; the evaluation and analysis
scripts sit outside it, which is why they are described as scripts rather than as
part of the evaluated system.

Two improvements were validated on the calibration batch and deliberately left
unapplied, since applying either would have required re-running every reported
result. They are kept as patches rather than merged:

- `PROPOSED_homoglyph_map_completion.patch` — completes L1's Cyrillic look-alike
  table. Under the evaluated configuration, homoglyph-bearing attacks are detected
  at 72.24 % [67.69, 76.36] over 407 instances; Appendix C of the thesis reports the
  paired coverage measurement behind this patch on the calibration batch.
- `PROPOSED_table_fpr_fix.patch` — addresses the external false positives, all of
  which fall on tabular documents (20 of 233, 8.6 %) and none on any user query.

Both are documented as known, measured improvements to a frozen system rather than
applied to it.

---

## Requirements

Python 3.11, roughly 8 GB of RAM for Mistral-7B in GGUF, and about 12 GB of disk for
the models and corpus. Developed and evaluated on an Apple MacBook Air (M4, 24 GB)
with Metal acceleration; no dedicated GPU is required.

## License

MIT. See [`LICENSE`](LICENSE).
