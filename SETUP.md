

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

---

## Project Structure
SecureRAG_Fixed/
├── chat.py                        <- Interactive chat interface
├── thesis_evaluation.py          <- Full academic evaluation (1,334 queries, 5 runs)
├── test_scenarios.py             <- Scenario-based evaluation
├── generate_charts.py             <- Generate thesis charts
├── download_datasets.py          <- Download BEIR/NQ datasets
├── download_models.py            <- Download model files
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

| Metric | Baseline | SecureRAG |
|--------|----------|-----------|
| Attack Success Rate | 100.0% | 8.96% (±0.59%) |
| False Positive Rate | 0.0% | 0.00% (±0.00%) |
| Mean Latency | 19.70 s | 6.09 s (±0.13 s) |
| Latency Reduction | — | 69.1% |

Results are the mean of 5 independent runs
(seeds: 42, 137, 271, 413, 509).
1,001 attack queries across 8 categories + 333 legitimate queries = 1,334 total.

---

## Notes

- Model files (.gguf) are not included — download separately via download_models.py
- Cache files are auto-generated on first run — delete before re-indexing
- All evaluation was conducted locally on Apple MacBook Air
  (M4, 24GB unified RAM, 512GB SSD) without any cloud dependency
