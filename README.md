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
| **L3** | Anomaly Detection | Scores the query across six statistical dimensions and blocks structurally anomalous input. |
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
42 for the thresholds, 137 and 271 for the output guardrail.

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

## Reproducibility

Every result reported in the thesis comes from a single frozen state of the defense
code: no module under `src/defenses/` and no line of `src/pipeline.py` changed
between the first evaluation run and the last. The evaluation scripts outside `src/`
were extended during that period; the defense itself was not.

That state is identified by [`evidence/CODE_FINGERPRINT.txt`](evidence/CODE_FINGERPRINT.txt),
which lists the SHA-256 digest of each of the twenty-six source files under `src/`
and carries its own digest on its final line:

```
21b7dac20dbb2f6fdc37074061bb45ccf3542b5edacbba022ed5f6ff50f287a4
```

To check a clone against it:

```bash
sed '$d' evidence/CODE_FINGERPRINT.txt | shasum -a 256
```

The value printed must be the one above. Any change to any of the twenty-six files,
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
