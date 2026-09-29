# Change-B4 — examiner revision round

Everything here answers a numbered comment from the examiners' report.
**No existing result file is modified.** All new output goes to `Change-B4/`.

---

## Run it

```bash
conda activate RAG
cd /path/to/SecureRAG

python3 changeb4/run_all.py --preflight              # 10 s: is everything present?
python3 changeb4/run_all.py --smoke                  # ~10 min: proves the plumbing
python3 changeb4/run_all.py --model Mistral-7B       # the real run (~8 h)
```

`run_all.py` skips any phase that already finished, so if the machine sleeps
or the run is interrupted, the same command resumes from where it stopped.

---

## Phases

| Phase | Items | Needs the model? | Time |
|---|---|---|---|
| 0 `phase0_offline.py` | A-3, A-12, A-21, A-22, A-23 | no | ~3 min |
| 0b `phase0b_heldout_and_public.py` | **A-2** (held-out templates + third-party sets) | no | ~4 min |
| 0c `phase0c_b64_rule.py` | **A-21** (base64 shape rule: measure and fix) | no | ~3 min |
| 0d `phase0d_audit.py` | audit of the fixes (anti-circularity) | no | ~2 min |
| 5 `phase5_full_pipeline_seeds.py` | **A-3, A-12, A-10** with L4 and the model | yes | ~1.5 h |
| 1 `phase1_external_baseline.py` | **A-7** | yes | ~5 h |
| 2 `phase2_internal_compliance.py` | A-1, A-8, A-9 (canary) | yes | ~1.5 h |
| 3 `phase3_real_benign.py` | A-20, A-6 | yes | ~1.5 h |
| 4 `phase4_analysis.py` | A-9 (ROC/PR), A-8 (kappa), A-10 | no | ~1 min |

Phases 0 and 4 need no GGUF and no FAISS index: layers L0–L3 read only the
query text, so every detection, attribution and ablation number that does not
involve L4 or latency is recomputed in seconds.

After phase 2, open `Change-B4/phase2/A8_manual_labelling_sheet.csv`, fill the
`human_verdict` column with `complied` or `resisted`, then re-run phase 4 to
get accuracy and Cohen's kappa (item A-8).

---

## Code that changed

Four existing files, all additive and all defaulting to the frozen behaviour:

| File | Change | Why |
|---|---|---|
| `src/config/settings.py` | appended `ZWSP_MODE`, `CANARY_TOKEN`, `get_zwsp_mode()`, `get_answer_prompt_template()` | A-22, A-9 |
| `src/defenses/sanitization/sanitize.py` | `_zero_width_replacement()` in `_normalize_unicode` | A-22 |
| `src/rag_core/generation/llm_engine.py` | uses `get_answer_prompt_template()` when present | A-9 |
| `run_external_eval.py` | `--no-defenses`, `--out-dir` | A-7 |
| `src/defenses/rules/rule_filter.py` | `B64_SHAPE_PATTERN` + decode-and-inspect | A-21 |

With no environment variables set, all four behave exactly as before:
`SECURERAG_ZWSP_MODE` defaults to `delete` and `SECURERAG_CANARY` to empty, so
the prompt is byte-identical to the frozen one.

New files: `changeb4/common.py`, `heldout_templates.py`, `phase0_offline.py`,
`phase0b_heldout_and_public.py`, `phase0c_b64_rule.py`, `phase0d_audit.py`,
`phase5_full_pipeline_seeds.py`,
`phase1_external_baseline.py`, `phase2_internal_compliance.py`,
`phase3_real_benign.py`, `phase4_analysis.py`, `run_all.py`.

---

## Configuration recorded for item A-15

| Setting | Value |
|---|---|
| Generator | Mistral-7B-Instruct **v0.2**, GGUF, **Q4_K_M** |
| Secondary | Llama-3.2-3B-Instruct, GGUF, Q4_K_M |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` (384-d) |
| Index | `faiss.IndexFlatIP` (exact inner product on normalised vectors) |
| Context window | 4096 tokens · max new tokens 512 · temperature 0.7 |
| Retrieval | top-k = 5 · chunk 800 / overlap 100 · relevance floor 0.15 |
| Thresholds | `ANOMALY_THRESHOLD` 15.0 · `SEMANTIC_THRESHOLD` 0.18 |
| Frozen commit | `61c113d` |

---

## Item A-2 (circularity) — what phase 0b does

**(b) Held-out templates.** Every attack tier's base-string pool (1,455 strings
in total) is split in half by hash: 754 dev, 701 test. Detection is reported on
each half separately. This shows whether the rules are fitted to the exact
strings they were written against; it does not prove they never saw the test
half, because the same author wrote both pools.

**(c) Third-party attacks.** Tensor Trust (Toyer et al., 2023) — 1,344 attacks
written by players of a public prompt-injection game, downloaded directly from
the project's repository. Nobody on this project wrote them. HackAPrompt is
added automatically when its CSV is reachable (HuggingFace) or passed with
`--hackaprompt-file`.

Add `--full-sample N --model Mistral-7B` to also run N of those third-party
attacks through the complete pipeline so the figure includes L4.

**AgentDojo is deliberately excluded** and the reason is written into the
results JSON: its injections live in tool-call results inside an agent loop,
which SecureRAG does not implement, so running it would measure a missing
component rather than the defense.

---

## Item A-21 (the base64 shape rule) — measured, then fixed

`rule_filter.py` contained a SHAPE rule, `r"(?:[A-Za-z0-9+/]{4}){10,}"`, that
blocked any 40+ character run of base64-alphabet characters as
`direct_injection / HIGH` without reading the content. Every SHA-256 digest,
git hash, JWT segment, PEM line and bcrypt hash matched it.

`B64_RULE_MODE` (default `shape`, the frozen behaviour) selects the
replacement, `decode`: the run is decoded, put through the same obfuscation
reversal L1 performs, and blocked only when it reads as language — a keyword,
or two or more common English words. A digest or a key decodes to bytes that
are not language and is left to L3.

Measured over five seeds, 5,005 attacks, 1,665 internal benign, 333 BIPIA
benign, and a 800-query technical set (all pre-L4):

| | shape (frozen) | decode (fix) |
|---|---|---|
| attack detection | 89.37 % | 88.43 % |
| FPR, technical queries **containing** a long run | **71.00 %** | **0.00 %** |
| FPR, realistic technical mix | **12.17 %** | **0.00 %** |
| FPR, internal benign generator | 0.00 % | 0.00 % |
| FPR, BIPIA benign | 1.80 % | 1.80 % |

The 0.94-point detection cost is measured **before L4**; the attacks that now
pass L2 are still scored by L3 and still reach the output guardrail, so the
full-pipeline cost is expected to be smaller. Phase 1 and 2 measure it.

---

## Recommended configuration

```bash
export SECURERAG_B64_RULE_MODE=decode
export SECURERAG_ZWSP_MODE=space
```

Measured over five seeds, pre-L4 (`phase0d_audit.py` prints the whole matrix):

| b64 rule | zero-width | detection | L1 / L2 / L3 blocks | internal FP | BIPIA FP |
|---|---|---|---|---|---|
| shape | delete (frozen) | 89.37 ± 0.69 | 161.4 / 708.2 / 25.0 | 0 / 1665 | 6 / 333 |
| shape | space | 89.55 ± 0.67 | 172.0 / 716.0 / 8.4 | 0 / 1665 | 6 / 333 |
| decode | delete | 88.43 ± 0.84 | 161.4 / 646.0 / 77.8 | 0 / 1665 | 6 / 333 |
| **decode** | **space** | **89.15 ± 0.75** | 172.0 / 699.6 / 20.8 | 0 / 1665 | 6 / 333 |

The two fixes interact. `space` restores the word boundaries L2 needs, which
recovers most of what `decode` gives up and keeps L3's own contribution close
to the frozen value. Net cost against the frozen configuration: **0.22 points
of pre-L4 detection**, inside one standard deviation, in exchange for removing
a false-positive class that blocked 71 % of technical queries containing a
long token and 92 % of a held-out set built from token types the fix never saw.

## Why the 0 % is not a fitted zero

`phase0d_audit.py` exists to try to break the fix:

1. **Held-out technical set** — different templates AND different token types
   (SSH keys, X.509 serials, IPFS CIDs, Ethereum addresses, Nix hashes,
   Kerberos blobs, GPG fingerprints). shape blocks 221/240; decode blocks 0/240.
2. **Not a disabled rule** — base64-wrapped payloads, including double-encoded
   ones, are still caught 12/12.
3. **A-9 gating** — across five seeds, zero attacks skip L4 because the anomaly
   score is zero, so the gate does not create a silent bypass.
4. **A-22** — what each layer reads is confirmed against `src/pipeline.py`:
   L1 sanitizes the original query, L2 reads the sanitized one, **L3 scores the
   ORIGINAL query**, retrieval and generation use the sanitized one.
5. **Full switch matrix** — four configurations, five seeds, attacks and both
   benign sets, so the recommendation is read off a table.
