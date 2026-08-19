

# SecureRAG

Five-layer adaptive defense framework against prompt injection attacks
in enterprise Retrieval-Augmented Generation (RAG) systems.

Evaluated on Mistral-7B — fully local, zero cloud dependency.

---

## Requirements

```bash
pip install sentence-transformers faiss-cpu numpy
pip install requests tqdm
```

---

## Setup

### 1. Place the model file
SecureRAG_Fixed/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf

### 2. Place corpus files
SecureRAG_Fixed/data/corpus/
<- Wikipedia files (doc1.txt ... doc300.txt)
<- Wikipedia extracted files (AA/, AB/, AC/)
<- SafeRAG files (saferag_nctd.txt)
<- BIPIA files (bipia_email.txt)
<- Knowledge base (rag_knowledge_base.txt, rag_master_knowledge_2025.txt)
<- BEIR corpus (beir_nq_corpus.txt, beir_scifact_corpus.txt)

### 3. Download BEIR datasets (one time only)

```bash
python3 download_datasets.py --dataset nq
python3 download_datasets.py --dataset scifact
```

Files are saved automatically to `data/corpus/` and `data/`.

### 3b. Domain-matched corpus (email + table), one time only

The BIPIA external validation set (`eval_set.json`/`fpr_set.json`) is
built from email/table documents. Comparing the model's response against
a Wikipedia-only corpus (L4's `similarity_score`) is an apples-to-oranges
comparison — it produced noisy, non-discriminating scores (root-caused
via `run_external_eval.py`/`run_external_fpr_eval.py`'s diagnostic
columns: real attack and real benign responses overlapped heavily in the
0.22–0.38 similarity range). Two additional, DOMAIN-MATCHED corpora are
added alongside Wikipedia (not replacing it) to give L4 a meaningful
reference space — both are entirely separate documents from the ones
used in `eval_set.json`/`fpr_set.json`, so there is no train/test overlap:

```bash
# Email domain: Enron Email Dataset (Kaggle mirror of the CMU/FERC
# public-domain corpus) -- requires `pip install kaggle` and a Kaggle API
# token once (see download_enron.py's docstring for the one-time setup).
python3 download_enron.py

# Table/structured-QA domain: BEIR/FiQA (financial forum Q&A) -- already
# supported by download_datasets.py, no extra setup needed.
python3 download_datasets.py --dataset fiqa
```

This writes `enron_emails_corpus.txt` and `beir_fiqa_corpus.txt` into
`data/corpus/` alongside the existing Wikipedia files — `FaissRetriever`
picks up every `.txt` file in that directory automatically.

### 4. Clear old cache (required before first run)

```bash
rm -f data/vector_index.faiss data/docs_cache.json data/embs_cache.npy
```

### 5. Run the chat interface

```bash
python3 chat.py
```

### 6. Run scenario-based evaluation

```bash
python3 test_scenarios.py
```

### 7. Run the full thesis evaluation (1,334 queries, 5 runs)

```bash
python3 thesis_evaluation.py
```

### 8. Generate charts

```bash
python3 generate_charts.py
```

### 9. (No model needed) Verify the L0 fix + the dynamic benign generator

Pure Python/regex checks that run in seconds, without loading the LLM,
embedder, or FAISS -- covers everything up to L3. Run this any time after
pulling changes, before spending hours on a full model run:

```bash
python3 verify_no_model.py
```

### 10. Diagnose false positives after a run

```bash
python3 diagnose_fpr.py
```

### 11. External validation (BIPIA, independent of this repo's own generator)

```bash
python3 build_eval_set.py        # needs BIPIA raw data under data/ (see script docstring)
python3 run_external_eval.py     # attack-side external ASR
python3 run_external_fpr_eval.py # benign-side external FPR (uses fpr_set.json)
python3 compare_chart.py         # internal vs external bar chart
```

---

## Project Structure
SecureRAG_Fixed/
├── chat.py                        <- Interactive chat interface
├── thesis_evaluation.py          <- Full academic evaluation (1,334 queries, 5 runs)
├── test_scenarios.py             <- Scenario-based evaluation
├── generate_charts.py             <- Generate thesis charts
├── download_datasets.py          <- Download BEIR/NQ datasets
├── download_models.py            <- Download model files
├── verify_no_model.py            <- L0/L1/L2/L3 regression check, no model needed
├── diagnose_fpr.py                <- Per-query FPR breakdown after a run
├── build_eval_set.py              <- Build external BIPIA attack eval set
├── run_external_eval.py           <- Run external BIPIA attack eval (ASR)
├── run_external_fpr_eval.py       <- Run external BIPIA benign eval (FPR)
├── compare_chart.py               <- Internal vs external bar chart
├── SETUP.md                       <- This file
│
├── data/
│   ├── corpus/
│   │   ├── doc1.txt ... doc300.txt    <- Wikipedia articles (300 docs)
│   │   ├── AA/ AB/ AC/               <- Wikipedia raw extracted files
│   │   ├── rag_knowledge_base.txt
│   │   ├── rag_master_knowledge_2025.txt
│   │   ├── bipia_email.txt
│   │   ├── saferag_nctd.txt
│   │   ├── beir_nq_corpus.txt
│   │   └── beir_scifact_corpus.txt
│   ├── beir_nq_queries.txt
│   ├── beir_scifact_queries.txt
│   ├── vector_index.faiss         <- Auto-generated (do not upload)
│   ├── docs_cache.json           <- Auto-generated (do not upload)
│   └── embs_cache.npy            <- Auto-generated (do not upload)
│
├── models/                        <- GGUF model files (do not upload)
│   └── mistral-7b-instruct-v0.2.Q4_K_M.gguf
│
├── outputs/
│   ├── final_evaluation_results_1334.csv
│   ├── evaluation_report.json
│   ├── session_stats.json
│   ├── plots/
│   │   ├── confusion_matrix.png
│   │   ├── layer_effectiveness.png
│   │   ├── latency_analysis.png
│   │   └── attack_distribution.png
│   └── thesis_v2/
│       ├── thesis_results.json
│       ├── thesis_latex_snippets.txt
│       └── plots/
│           ├── fig_multirun_summary.png
│           ├── fig_ablation_study.png
│           ├── category_multirun.png
│           └── latency_analysis_v2.png
│
├── src/
│   ├── pipeline.py                <- Main 5-layer defense pipeline
│   ├── attacks/
│   │   └── generator.py          <- Hybrid attack generator (8 categories)
│   ├── config/
│   │   └── settings.py            <- Central configuration
│   ├── defenses/
│   │   ├── sanitization/
│   │   │   └── sanitize.py      <- L1: Input sanitization
│   │   ├── rules/
│   │   │   └── rule_filter.py    <- L2: Rule-based pattern filter
│   │   ├── anomaly/
│   │   │   └── anomaly_detector.py <- L3: Statistical anomaly detection
│   │   └── semantic/
│   │       └── semantic_detector.py <- L4: Semantic output guardrail
│   └── rag_core/
│       ├── embeddings/
│       │   └── embedder.py      <- Sentence-BERT embeddings
│       ├── retrieval/
│       │   └── faiss_engine.py    <- FAISS vector search
│       └── generation/
│           └── llm_engine.py     <- Mistral-7B via llama-cpp
│
└── wikiextractor/               <- Wikipedia extraction utilities
├── WikiExtractor.py
├── extract.py
├── clean.py
├── extractPage.py
└── cirrus-extract.py

---

## Defense Layers

| Layer | Component | Function |
|-------|-----------|----------|
| L0 | Adaptive Risk Sensor | Classifies query risk (LOW / MEDIUM / HIGH) |
| L1 | Input Sanitization | Removes Base64, homoglyphs, zero-width characters |
| L2 | Rule-Based Filter | Matches 8 known attack pattern categories |
| L3 | Anomaly Detection | Scores queries across 6 statistical dimensions |
| L4 | Semantic Guardrail | Validates model output against knowledge base |

---

## Evaluation Results

**Read this table historically, in order -- each row superseded the one
above it as bugs were found and fixed. Do not cite the top rows.**

| Version | ASR | FPR | Mean Latency | Note |
|---|---|---|---|---|
| Original (superseded) | 8.96% (±0.59%) | 0.00% (±0.00%) | 6.09 s (±0.13 s) | FPR measured on only 12 unique benign questions, oversampled with replacement to reach 333 -- an artificially perfect number, not a valid measurement. |
| First correction (superseded) | 8.90% (±0.52%) | 1.50% (±0.56%) | 7.905 s (±2.305 s) | Benign set expanded to 333 genuinely distinct hand-written questions (no duplicates). χ²=909.0, p<0.001 (McNemar), Wilson 95% CI [1.02%, 4.27%]. Root cause of all 6 false positives traced to a bare-keyword list in `pipeline.py`'s L0 pre-screen. |
| **Current code (this commit) -- not yet re-run** | pending | pending | pending | L0 fixed: reuses the same context-required regex tiers as L2 instead of bare-keyword substring matching (see `src/defenses/rules/rule_filter.py::quick_high_risk_scan`). Benign queries are now generated dynamically at request time from independent template x topic pools (`BenignQueryGenerator`) instead of sampled from any static list -- draws are always duplicate-free. Run `python3 verify_no_model.py` for an instant, model-free sanity check, then `python3 thesis_evaluation.py` (5 seeds: 42, 137, 271, 413, 509) for the real numbers. |

1,001 attack queries across 8 categories + 333 legitimate queries = 1,334 total per run.

---

## Notes

- Model files (.gguf) are not included — download separately via download_models.py
- Cache files are auto-generated on first run — delete before re-indexing
- All evaluation was conducted locally on Apple MacBook Air
  (M4, 24GB unified RAM, 512GB SSD) without any cloud dependency
