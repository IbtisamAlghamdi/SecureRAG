# SecureRAG

A five-layer, training-free defense framework that protects Retrieval-Augmented
Generation systems against prompt injection. It runs entirely on locally deployed
open-weight models, with no dependency on external APIs.

This repository holds the implementation and the evaluation code for the master's
thesis *SecureRAG: A Five-Layer Adaptive Defense Framework for Enterprise
Retrieval-Augmented Generation Systems*.

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

Mistral-7B-Instruct v0.2, five seeds (42, 137, 271, 413, 509), 1,001 attacks and
333 legitimate queries per run.

| | Result |
|---|---|
| Attack success rate | **9.77 % ± 1.08 %** (undefended baseline: 100 %) |
| False positive rate | **0.12 % ± 0.16 %** |
| Mean latency | **6.90 s ± 0.48 s** (undefended baseline: 17.84 s) |
| External benchmark (BIPIA, 986 attacks) | 84.08 % neutralised end-to-end |

Full breakdown, including the cross-model evaluation on Llama-3.2-3B and the
external BIPIA validation, is in [`FINAL_RESULTS.md`](FINAL_RESULTS.md).

---

## Project structure

```
SecureRAG/
├── src/
│   ├── pipeline.py                     the five-layer pipeline; L0 lives here    (325)
│   ├── config/
│   │   └── settings.py                 all thresholds and model paths            (129)
│   ├── defenses/
│   │   ├── sanitization/sanitize.py    L1  input sanitization                    (294)
│   │   ├── rules/rule_filter.py        L2  nine rule tiers                       (502)
│   │   ├── anomaly/anomaly_detector.py L3  six-dimension anomaly score           (336)
│   │   └── semantic/semantic_detector.py L4 output guardrail                     (127)
│   ├── attacks/
│   │   └── generator.py                attack and benign generators              (841)
│   └── rag_core/
│       ├── embeddings/embedder.py      Sentence-BERT                              (64)
│       ├── retrieval/faiss_engine.py   FAISS index                               (112)
│       └── generation/llm_engine.py    GGUF model loader                          (92)
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

Every result reported in the thesis comes from a single frozen state of the defense code: no module
under `src/defenses/` and no line of `src/pipeline.py` changed between the first
evaluation run and the last. The evaluation scripts outside `src/` were extended
during that period; the defense itself was not.

Two validated improvements were deliberately left unapplied for the same reason, and
are kept here as patches rather than merged:

- `PROPOSED_homoglyph_map_completion.patch` — completes L1's Cyrillic look-alike
  table, raising homoglyph-variant detection from 73.9 % to 88.1 % at no measured
  false-positive cost.
- `PROPOSED_table_fpr_fix.patch` — lowers the external false-positive rate from
  1.80 % to 0.30 % at a cost of one missed attack in 1,001.

Applying either would have required re-running every reported result, so both are
documented as known, quantified improvements instead.

---

## Requirements

Python 3.11, roughly 8 GB of RAM for Mistral-7B in GGUF, and about 12 GB of disk for
the models and corpus. Developed and evaluated on an Apple MacBook Air (M4, 24 GB) with Metal
acceleration; no dedicated GPU is required.

## License

MIT. See [`LICENSE`](LICENSE).
