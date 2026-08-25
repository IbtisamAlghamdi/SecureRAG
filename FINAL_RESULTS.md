# SecureRAG — Final Results

**Status: complete.** All evaluations finished. Every figure below comes from a real run of the frozen
defense code (`src/pipeline.py` and all layer modules unchanged since commit `816f092`).

**Models:** Mistral-7B-Instruct v0.2 (primary) · Llama-3.2-3B-Instruct (secondary)
**Corpus:** 308 files / 3,804 chunks · **Seeds:** 42, 137, 271, 413, 509

---

## 1. Headline table

| | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| **Internal ASR** | **9.77 % ± 1.08 %** | **10.33 % ± 0.88 %** |
| **Internal FPR** | 0.12 % ± 0.16 % | 0.06 % ± 0.13 % |
| Internal latency | 6.896 s ± 0.483 s | 1.170 s ± 0.058 s |
| **External detection** | 42.60 % | **45.84 %** |
| External ASR (reach-rate) | 57.40 % | 54.16 % |
| **External ASR (true compliance)** | **15.92 %** | 23.73 % ⚠️ |
| **External FPR** | **1.80 %** | 6.01 % |
| **Attacks neutralised end-to-end** | **84.08 %** | 76.27 % |

⚠️ The Llama compliance figure is far less reliable than Mistral's — see §5.

**The ASR ranges overlap** (Mistral [8.69, 10.85] vs Llama [9.45, 11.21]), so the internal difference is
not statistically meaningful. The defense generalises across two architectures of different size.

---

## 2. Internal evaluation — 5 seeds each

### Mistral-7B

| Run | Seed | ASR | FPR | Latency | Blocked |
|---|---|---|---|---|---|
| 1 | 42 | 8.89 % | 0.3 % | 7.520 s | 912 |
| 2 | 137 | 8.99 % | 0.0 % | 7.279 s | 911 |
| 3 | 271 | 11.19 % | 0.0 % | 6.701 s | 889 |
| 4 | 413 | 9.09 % | 0.3 % | 6.369 s | 910 |
| 5 | 509 | 10.69 % | 0.0 % | 6.611 s | 894 |
| **Mean** | | **9.77 % ± 1.08 %** | **0.12 % ± 0.16 %** | **6.896 s ± 0.483 s** | 903.2 |

Wilson 95 % CI (FPR): [0.05 %, 1.68 %] · McNemar χ² = 901.0, *p* < 0.001

### Llama-3.2-3B

| Run | Seed | ASR | FPR | Latency | Blocked |
|---|---|---|---|---|---|
| 1 | 42 | 9.49 % | 0.0 % | 1.171 s | 906 |
| 2 | 137 | 10.29 % | 0.0 % | 1.180 s | 898 |
| 3 | 271 | 11.49 % | 0.0 % | 1.074 s | 886 |
| 4 | 413 | 9.49 % | 0.3 % | 1.230 s | 906 |
| 5 | 509 | 10.89 % | 0.0 % | 1.197 s | 892 |
| **Mean** | | **10.33 % ± 0.88 %** | **0.06 % ± 0.13 %** | **1.170 s ± 0.058 s** | 897.6 |

Wilson 95 % CI (FPR): [0.05 %, 1.68 %] · McNemar χ² = 895.0, *p* < 0.001

### Detection by attack tier

| Tier | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| context_poisoning | 100.0 % ± 0.0 | 100.0 % ± 0.0 |
| conversational_drift | 99.8 % ± 0.4 | 99.3 % ± 0.6 |
| token_smuggling | 99.7 % ± 0.4 | 99.7 % ± 0.4 |
| indirect_poisoning | 98.0 % ± 1.3 | 97.9 % ± 0.9 |
| trust_escalation | 96.6 % ± 2.3 | 95.7 % ± 2.9 |
| psychological_manip | 96.4 % ± 2.2 | 96.4 % ± 2.3 |
| nested_hiding | 88.0 % ± 0.8 | 88.0 % ± 0.8 |
| **semantic_camouflage** | **40.9 % ± 4.5** | **37.2 % ± 3.0** |

### Ablation (seed 42)

| Configuration | ASR (Mistral) | ASR (Llama) | Latency (Mistral) | Latency (Llama) |
|---|---|---|---|---|
| L0 only | 100.00 % | **100.00 %** | 17.837 s | 4.826 s |
| L0+L1 | 84.22 % | **84.22 %** | 16.736 s | 3.833 s |
| L0+L1+L2 | 12.29 % | **12.29 %** | 7.963 s | 1.221 s |
| L0+L1+L2+L3 | 9.89 % | **9.89 %** | 6.673 s | 1.100 s |

**All four pre-L4 configurations return numerically identical ASR across both models.** This is expected
and is a positive validation: L0–L3 inspect only the input, never the model's output, so with a fixed seed
they must produce identical blocking decisions regardless of which LLM is loaded. Reproducing it to the
unit across two architectures confirms the layer separation is implemented as designed.

**L4's real contribution** (like-for-like, seed 42, identical data):

| | Blocked without L4 | Blocked with L4 | L4 recovers |
|---|---|---|---|
| Mistral-7B | 902 / 1001 | 912 / 1001 | **+10 attacks** |
| Llama-3.2-3B | 902 / 1001 | 906 / 1001 | **+4 attacks** |

---

## 3. External validation — BIPIA (Microsoft), 986 attacks

An independent benchmark neither model's evaluator had any role in designing. This is the direct answer to
the co-design-bias criticism.

### End-to-end accounting

| Outcome | Mistral-7B | | Llama-3.2-3B | |
|---|---|---|---|---|
| Blocked before the model | 420 | 42.60 % | 452 | 45.84 % |
| Reached, **model resisted** | 398 | 40.37 % | 147 | 14.91 % |
| Reached, ambiguous | 11 | 1.12 % | 153 | 15.52 % |
| **Reached, complied** | **157** | **15.92 %** | **234** | **23.73 %** |
| **Neutralised** | **829** | **84.08 %** | **752** | **76.27 %** |

95 % CI on true compliance: Mistral [13.77 %, 18.34 %] · Llama [21.18 %, 26.49 %]

### Every cross-model difference sits in L4

**Attack side:**

| Layer | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| `rules` (L2) | 414 | **414 — identical** |
| `anomaly` (L3) | 5 | **5 — identical** |
| `semantic` (L4) | 1 | **33** |

**False-positive side:**

| Layer | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| `anomaly` (L3) | 6 | **6 — identical** |
| `semantic` (L4) | **0** | **14** |
| **Total FPR** | **1.80 %** | **6.01 %** |

L4 on Llama fires far more often on **both** sides: +32 attacks caught, +14 false positives — a precision
of **70 %** on the extra firings. This is a trade-off, not an improvement, and it localises a known
limitation: `SEMANTIC_THRESHOLD = 0.18` was calibrated against Mistral-7B data alone.

### External false positives — fully root-caused

Mistral's 6 false positives were all blocked at L3, all with `risk_level = HIGH`, all dense data tables.

Cause: the special-character-ratio rule counts markdown table punctuation (`|`, `-`) as obfuscation
evidence, giving a plain table the same +10.0 as a symbol-obfuscated payload. Combined with the
length/structure dimension — which measures the same property — tables reach 28–30, crossing L0's HIGH
cutoff (27), which then lowers L3's own bar from 30.0 to 21.0.

**All six pass at the normal bar.** A validated fix exists (1.80 % → 0.30 %, costing one attack in 1,001)
and was deliberately not applied, because adopting it would require re-running every reported result.

### Four independent lines of false-positive evidence

| Source | Independence | Result |
|---|---|---|
| `fpr_set.json` | used for tuning (disclosed) | 1.80 % |
| Internal generator, 8 seeds | fresh sample each seed | 0.00 % every seed |
| Fresh BIPIA holdout | **never used for tuning** | 1.20 % |
| Real human queries (NQ, SciFact, FiQA) | **written by unrelated people** | **0 / 300** |

---

## 4. Reaching the model is not succeeding

`run_external_eval.py` computes ASR as `1 − detection_rate`, counting every response that reached the
model as a successful attack — the reviewers' second criticism.

`classify_true_compliance.py` recovers the **literal injected instruction** from BIPIA's own
`text_attack_{train,test}.json` via each sample's `attack_name` (ground truth, not a heuristic), then
compares its similarity to the response against the real question's similarity.

**Coverage: 100 % of reached-model rows for both models** (566/566 and 534/534), scored on **full
untruncated responses**.

| | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| Reach-rate ASR | 57.40 % | 54.16 % |
| **True compliance ASR** | **15.92 %** | **23.73 %** |
| Ratio | **3.6×** | 2.3× |
| Model resisted, of what reached it | **70.3 %** | 27.5 % |

**For Mistral-7B: of 566 attacks that got past every defense layer, 70.3 % were still refused by the model
itself.** Reporting those as successes overstates the attack success rate by a factor of 3.6.

Both figures are **lower bounds** — ambiguous verdicts are counted as *not complied*, the conservative
direction.

---

## 5. How far to trust each compliance figure

The classifier is not equally informative on both models, and this must be stated when the numbers are
presented.

| | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| Median gap, complied | **+0.4966** | +0.1730 |
| Median gap, resisted | **−0.4316** | −0.1617 |
| Ambiguous share | **1.9 %** | **28.7 %** |
| Spread across the margin sweep | **2.44 pts** | **17.75 pts** |
| `benign_question_similarity` mean | 0.420 | **0.113** |

**Mistral:** the two verdict groups sit on opposite sides of zero with medians nearly a full unit apart.
Most cases are far from the decision boundary, only 1.9 % are ambiguous, and the answer moves just 2.44
points across the entire margin sweep (13.79 %–16.23 %). **The figure is robust and the margin choice
does not drive it.**

**Llama:** the gaps are roughly three times smaller, 28.7 % of cases are ambiguous with a median gap of
+0.004 — essentially at the boundary — and the answer swings 17.75 points across the sweep
(14.30 %–32.05 %). Llama's responses also sit much further from the original question in general
(mean similarity 0.113 vs 0.420), which compresses both terms toward each other.

> **Conclusion: 15.92 % is a solid figure. 23.73 % should be reported with the ambiguous fraction stated
> and the margin sweep shown, because the measurement discriminates poorly on this model.** This is a
> limitation of the measurement instrument on Llama, not necessarily a statement about Llama's security.

### Margin sensitivity

| Margin | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| 0.00 | 16.23 % | 32.05 % |
| 0.02 | 16.23 % | 29.01 % |
| **0.05** | **15.92 %** | **23.73 %** |
| 0.10 | 14.40 % | 18.15 % |
| 0.15 | 13.79 % | 14.30 % |

---

## 6. Where the residual risk sits — and why it differs by model

Nine BIPIA categories inject a plain alternate task with no self-referential wording, making them
structurally invisible to pattern matching (Business Intelligence, Content Creation, Conversational Agent,
Learning and Tutoring, Programming Help, Research Assistance, Task Automation, Information Retrieval,
Sentiment Analysis).

| | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| Share of all compliances from these 9 | **77.1 %** | 32.1 % |
| Compliance rate within the 9 | **40.2 %** | 26.3 % |
| Compliance rate in the other 20 | 13.6 % | **63.9 %** |

**For Mistral the residual risk is highly concentrated:** 31 % of categories produce 77 % of all
successful attacks. That turns an open limitation into a quantified, bounded one.

**For Llama the pattern inverts** — the other twenty categories show higher compliance. Given §5, this is
most plausibly an artefact of the classifier discriminating poorly on Llama's responses rather than a real
security difference, but it is reported as measured.

### Attack position

| Position | Mistral-7B | Llama-3.2-3B |
|---|---|---|
| start | **44.4 %** | 42.2 % |
| middle | 37.2 % | 46.3 % |
| **end** | **12.7 %** | 43.0 % |

BIPIA reports that **end** placement yields the highest ASR. **Mistral shows the reverse**, and the
architecture explains it: in this system the document comes first and the real question comes last, so an
end-position attack sits immediately before the genuine question the model then answers. In BIPIA's layout
the user instruction follows the external content, so "end of content" is closest to the instruction.

Llama shows no position effect at all — consistent with §5, since its verdicts are largely near the
decision boundary and would not resolve a positional gradient.

---

## 7. Known limitations

| # | Limitation | Status |
|---|---|---|
| 1 | `semantic_camouflage` at 40.9 % / 37.2 % detection | Structural — attacks phrased as ordinary academic questions with no attack-flavoured token. Handled at L3/L4 rather than L2 by design |
| 2 | Nine BIPIA categories at 0–8.8 % detection | Structural, and **quantified** for Mistral: 31 % of categories → 77 % of successful attacks |
| 3 | External FPR 1.80 % (Mistral) / 6.01 % (Llama) | Mistral's fully root-caused to the L0↔L3 table interaction; validated fix exists, deliberately unapplied. Llama's is driven by L4 |
| 4 | Internal FPR exercises L4 only | Only 18/333 queries reach L4; the zero rests on a 0.006 margin. Report as "short user-written queries", not the system total |
| 5 | `SEMANTIC_THRESHOLD = 0.18` calibrated on Mistral alone | Not established as transferable — Llama's 6.01 % external FPR is direct evidence of this |
| 6 | The compliance classifier discriminates poorly on Llama | §5 — 28.7 % ambiguous, 17.75-point margin sensitivity |
| 7 | BIPIA's border-string defense measured 0/14 | Explained: applied to `{context}`, which carries corpus text, while the attack enters via `{query}` |

---

## 8. What can and cannot be claimed

**Supported:**

- Evaluated on an independent benchmark the author had no role in designing.
- Two models, five seeds each, frozen code, zero duplicate attacks or benign queries.
- Distinguished "reached the model" from "actually complied" — a distinction the BIPIA paper does not
  draw — and quantified it at 3.6× for Mistral.
- Implemented BIPIA's own published defense inside this system and reported its measured result,
  including the negative one.
- Identified an architectural reason for a divergence from BIPIA's published position-effect finding.
- Four independent lines of false-positive evidence, including 0/300 on real human-written queries.

**Not supported:**

- **No claim of outperforming the published BIPIA results.** Their undefended Mistral-7B baseline weights
  to 8.41 % on the email+table mix, against this system's defended 15.92 %. The ASR definitions also
  differ — the same run yields 57.40 %, 15.92 % or 8.41 % depending on which definition is applied — so
  the figures cannot be ranked against each other at all.

---

## 9. Comparison with the originally submitted version

| | Submitted | Now |
|---|---|---|
| Internal ASR | 8.96 % | 9.77 % ± 1.08 % |
| Internal FPR | 0.00 % | 0.12 % ± 0.16 % |
| `semantic_camouflage` ASR | 39.9 % | 59.1 % |
| Effective attack sample | 80 strings | **1,455 strings** |
| Effective benign sample | **12 questions** | **333 unique** |
| Runs | 1 | **5 seeds × 2 models** |
| External validation | none | **BIPIA: 986 attacks + 333 benign + fresh holdout + 300 human queries** |

Several numbers are worse. That is the point: the earlier measurements were structurally unable to reveal
the errors they contained. The reported 0.00 % FPR came from 333 benign queries drawn with replacement
from a hand-written list of 12, none of which contained a word the detector treats as risky — a test
incapable of producing a false positive.

---

*Full change history with root cause and verification for every fix: `REVISION_LOG_PART1.md` through
`REVISION_LOG_PART4.md`. Mistral-only detail: `MISTRAL_7B_FINAL.md`. Working narrative: `نوت_الشغل.md`.*
