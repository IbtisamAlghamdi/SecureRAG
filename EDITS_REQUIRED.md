# Required Edits — SecureRAG thesis, Chapters 1–5 + Appendices

Every item below was checked against the source tree or against a measurement run
during this review. Nothing here is inferred.

**Verdict:** 27 edits. 2 are fabricated claims with no source and must be deleted.
5 contradict the current code. 8 are wrong numbers. 5 are LaTeX faults (one of them
silently destroys a paragraph). The rest are stale framing or mislabels.

---

## PART 1 — CLAIMS WITH NO SOURCE (delete; do not reword)

### E1 — Ch3 §3.2.5 (`subsec:retrieval`) · retrieval threshold 0.15
Searched the whole repository: no calibration experiment, no 50-query validation set,
no 8 % figure, no 0.10/0.20 bounds. The only record of this number's origin is
`threshold_sensitivity_analysis.py` line 14, which states the *opposite* — that 0.15
was picked by reasoning from an existing threshold, not from a sweep.

**BEFORE**
> This threshold was determined empirically through a calibration experiment on a held-out validation set of 50 queries drawn from the evaluation corpus before the main evaluation began. The value of 0.15 was chosen as the point at which retrieval failure---returning no usable documents for legitimate queries---was minimized without admitting weakly related content that would raise context poisoning risk. Thresholds below 0.10 allowed irrelevant documents through to the language model, while thresholds above 0.20 caused retrieval failure on approximately 8\% of legitimate queries in the validation set. The selected value sits within the empirically observed stable range between these two bounds.

**AFTER**
> This value is an inherited default rather than a calibrated choice: no derivation for it exists on record, and it was never swept. It is reported as such in Section~\ref{subsec:retrieval_threshold}, which also explains why disclosing it matters --- the argument that first moved the L4 semantic threshold to 0.15 rested on consistency with this number.

---

### E2 — Ch3 §3.3.1 (`subsec:l0`) · the "50 + 50 BIPIA" calibration
No such experiment exists. The only 50+50 in the repository is `quick_sample_test.py`
(`N_INTERNAL = 50`, `N_EXTERNAL = 50`), which is 50 internal **attacks** plus 50
external **attacks** — not 50 attacks and 50 benign — and its own docstring describes
it as a read-only quick-signal harness used to test BIPIA's border-string defense. It
never touched L0. The passage is also internally impossible: BIPIA is an external
benchmark, so it cannot be "held out from the 1,334-query main evaluation dataset",
which is entirely self-generated.

**BEFORE**
> These multiplier boundaries were established through iterative manual testing on a development sample of 50 attack queries and 50 legitimate queries drawn from the BIPIA benchmark~\cite{yi2025benchmarking}, held out from the 1{,}334-query main evaluation dataset to prevent data leakage. The MEDIUM boundary of 1.0 times the base anomaly threshold marks the point at which the anomaly score begins to deviate from the distribution observed in benign development queries: below this value, scores were indistinguishable from the benign baseline, while above it, at least one structural risk signal was consistently present. The HIGH boundary of 1.8 was selected because queries above this level consistently exhibited multiple co-occurring signals---such as elevated keyword density combined with obfuscation indicators---that warranted activating both the stricter L3 threshold and L4 simultaneously.
>
> The empirical support for these boundaries is provided in Section~\ref{subsec:fpr}, where the false positive rate of 0.12\%,($\pm$0.16\%)across 333 legitimate queries confirms that the LOW classification correctly excludes the great majority of benign inputs from L4 evaluation. A formal grid search over a larger calibration set would provide stronger statistical grounding; this limitation is acknowledged as part of the threshold selection procedure.

**AFTER**
> These boundaries are not independent parameters. Both are multiples of the single anomaly threshold whose selection is documented in Section~\ref{subsec:l3_threshold}, and they inherit whatever justification that sweep establishes for the anchor. More importantly, L0 has no blocking authority: it returns a classification that modulates two later decisions --- it lowers L3's effective bar for HIGH-risk queries and it opens L4's gate --- but no query is ever rejected on L0's authority. L0 therefore cannot produce a false positive on its own, and has no threshold requiring separate calibration.
>
> The measured effect of the classification on the benign side is reported in Section~\ref{subsec:fpr}: across the 333 legitimate queries of the representative run, every query was classified LOW, 315 scored exactly zero across all six anomaly dimensions and were exempt from L4, and the remaining 18 were passed to L4 for checking.

---

## PART 2 — CONTRADICTS THE CURRENT CODE

`src/pipeline.py` gates L4 as
`if response and (risk_level in ["HIGH","MEDIUM"] or anomaly_score > 0):`
A LOW-risk query is exempt **only** when its anomaly score is exactly zero. Four
places still describe the superseded gate, in which LOW always bypassed L4.

### E3 — Ch3 §3.3.1 (`subsec:l0`), final paragraph
**BEFORE**
> Only MEDIUM and HIGH-risk queries activate L4; queries classified as LOW bypass the semantic guardrail entirely---and this selective deactivation is the mechanism that keeps the false positive rate near zero~\cite{ramakrishnan2025securing,liu2024formalizing}.

**AFTER**
> L4 runs when L0 returned MEDIUM or HIGH, or when the anomaly score is greater than zero on any of the six dimensions L3 measures; a LOW-risk query is exempt only when that score is exactly zero. This gating is the mechanism that keeps the false positive rate near zero: on the representative benign batch it sent 18 of 333 queries to L4 rather than all 333~\cite{ramakrishnan2025securing,liu2024formalizing}.

### E4 — Ch3 §3.3.5 (`subsec:l4`)
**BEFORE**
> L4 activates only for queries classified as MEDIUM or HIGH risk by L0. Queries classified as LOW risk bypass the semantic guardrail entirely. This selective activation is the design decision that keeps the false positive rate near zero: most legitimate queries about topics that superficially resemble injection language---such as questions about anomaly detection or quantization---are never evaluated by L4 at all. The small residual share that does reach L4 (Section~\ref{subsec:fpr}) is where the two observed false positives occurred~\cite{chen2025defense,liu2024formalizing,ramakrishnan2025securing}.

**AFTER**
> L4 activates when L0 classified the query MEDIUM or HIGH risk, or when its anomaly score is non-zero on any of the six dimensions L3 measures. A LOW-risk query bypasses the guardrail only if that score is exactly zero. This gating is the design decision that keeps the false positive rate near zero: on the representative benign batch, 315 of 333 legitimate queries scored zero and were never evaluated by L4 at all. The 18 that did reach it (Section~\ref{subsec:fpr}) are the only population in which an internal false positive is possible, and both observed false positives occurred there~\cite{chen2025defense,liu2024formalizing,ramakrishnan2025securing}.

### E5 — Ch3 Algorithm 1 (`alg:securerag`), Step 6
**BEFORE**
> 	\tcp{Step 6 — Check response (only for MEDIUM and HIGH risk)}
> 	\If{risk is MEDIUM or HIGH}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

**AFTER**
> 	\tcp{Step 6 — Check response (unless LOW risk with a zero anomaly score)}
> 	\If{risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

### E6 — Ch3 Algorithm 2 (`alg:boundaries`), Enforcement Point 3
**BEFORE**
> 	\If{risk is MEDIUM or HIGH \textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

**AFTER**
> 	\If{(risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$) \textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

### E7 — Ch5 §5.2 (`sec:contributions_summary`), second contribution
Two faults: the false positive rate is 0.12 %, not zero; and the ablation study does
not test removing L0 — it adds L1–L4 cumulatively, so it cannot support this claim.
The claim *is* supportable, but from the L4-gating measurement, not from the ablation.

**BEFORE**
> This architectural decision is what keeps the false positive rate at zero across the full evaluation dataset. Without the ARS, uniform application of all five layers to every query would introduce false positives, as confirmed by the ablation results in Section~\ref{subsec:ablation}.

**AFTER**
> This architectural decision is what holds the false positive rate at 0.12\%\,($\pm$0.16\%). Without it, L4 would run on all 333 legitimate queries per batch rather than the 18 that carry any structural signal at all, and every one of them would become a candidate for a false positive.

---

## PART 3 — WRONG NUMBERS

### E8 — Ch4 §4.5.3 (`subsec:layers`) · "8.2 %"
$(24+10)/912 = 3.7\,\%$. The figure 8.2 % is $(34+41)/910$ — the superseded
ablation-derived layer table, not the per-query measurement now reported.

**BEFORE**
> The primary source of run-to-run variation arises from the L3 anomaly threshold and the L4 semantic similarity comparison, though these together account for only 8.2\% of all blocked queries.

**AFTER**
> L3 and L4 together account for only 3.7\% of all blocked queries in this run (34 of 912).

### E9 — Ch4 §4.5.3 (`subsec:layers`) · L1/L2 variance
Measured across the five seeds: L1 = 161.4 ($\pm$10.3, range 149–173),
L2 = 708.2 ($\pm$13.3, range 691–720), L3 = 25.0 ($\pm$2.2). L2's variation is
*larger* than L3's, not negligible. The layers are deterministic given a query; the
counts vary because each seed draws a different attack mix.

**BEFORE**
> Blocking counts for L1 and L2 are largely deterministic---both apply fixed rules and patterns---so variance across runs is negligible.

**AFTER**
> L1 and L2 are deterministic given a query --- both apply fixed rules and patterns --- but their counts still vary across runs, because each seed draws a different mix of attack categories and obfuscation variants. Measured over the five seeds: L1 blocks 161.4 ($\pm$10.3), L2 708.2 ($\pm$13.3), L3 25.0 ($\pm$2.2).

### E10 — Ch4 Figure caption (`fig:category_multirun`)
Contradicts Table~\ref{tab:category_results} on the same page. Token smuggling is
99.7 $\pm$ 0.4; context poisoning is the category at 100.0 $\pm$ 0.0.

**BEFORE**
> Token smuggling achieves perfect detection (DR = 100\%) with zero variance.

**AFTER**
> Context poisoning achieves perfect detection (DR = 100.0\%) with zero variance across all five runs.

### E11 — Ch4 §4.6 and Ch5 §5.2 · the ablation summary sentence (appears twice, identical fix)
Two faults. "Removing L2 alone" describes the L0+L1 configuration, which also lacks
L3 and L4 — it is not L2 in isolation. And 2.52 pp subtracts a five-seed mean
(9.77 %) from a single-seed ablation value (12.29 %). Like-for-like on seed 42 the
figure is $12.29 - 8.89 = 3.40$ pp.

**BEFORE**
> the ablation study confirmed that each layer contributes individually: removing L2 alone raises the ASR from $9.77\%$ to $84.22\%$, and removing L3 and L4 leaves a further $2.52$ percentage points of attacks undetected.

**AFTER**
> the ablation study confirmed that each layer contributes individually: on seed~$=42$, the L0+L1 configuration records an ASR of $84.22\%$ against $12.29\%$ once L2 is added, and adding L3 and L4 to that configuration removes a further $3.40$ percentage points, from $12.29\%$ to $8.89\%$.

### E12 — Ch4 §4.5.5 (`subsec:fpr`) · the false-positive example
`settings.py` records that the Python-subclass and `.gitignore` responses score
0.186–0.2331 — **above** the 0.18 threshold, i.e. they pass. They are the queries the
threshold was set to protect, not the queries that were blocked. The two actual false
positives scored below 0.18 and are not identified in any log available here.

**BEFORE**
> The two observed false positives occurred at L4, on legitimate but security-adjacent questions (for example, asking how to override a method in a Python subclass) whose corpus-similarity score fell only marginally below the semantic threshold.

**AFTER**
> Both observed false positives occurred at L4, on responses whose corpus-similarity score fell below the 0.18 semantic threshold. The margin involved is narrow: the five internal benign responses that sit closest to the boundary score between 0.186 and 0.2331, so the threshold separating them from a block is 0.006.

### E13 — Ch4 §4.5.10 (`subsec:demo`)
Appendix~B now contains ten attack examples, not nine.

**BEFORE**
> covering five legitimate queries and nine attack attempts drawn from all eight injection categories

**AFTER**
> covering five legitimate queries and ten attack attempts drawn from all eight injection categories

### E14 — Ch5 §5.3 (`sec:limitations`), opening line
Six limitations are listed, not four.

**BEFORE**
> Four limitations bound the scope of these findings, and all four must be taken into account when interpreting the evaluation outcomes.

**AFTER**
> Six limitations bound the scope of these findings, and all six must be taken into account when interpreting the evaluation outcomes.

### E15 — Ch4 §4.5.8 (`subsec:sc_analysis`) · the homoglyph contradiction
The paragraph states that encoding makes attacks easier to detect and that plain text
is the hardest case, but Table~\ref{tab:sc_variants} directly below shows homoglyph at
8.2 % — worse than plain text at 18.2 %. That inversion is the reason the missing
Cyrillic mappings were found (Ch5 §5.4), so it should point forward rather than be
contradicted.

**BEFORE**
> Obfuscation-encoded variants are, counter-intuitively, easier to detect than plain text: Base64-encoded semantic camouflage attacks are detected at $100.0\%$, and zero-width-character variants at $84.3\%$, because the act of encoding is itself a strong structural signal independent of the underlying intent. The genuinely hard case is the plain-text form, detected at only $18.2\%$, since it is precisely this form---an ordinary-sounding academic or creative question with no encoding, no injected instruction, and no structural anomaly---that the category is designed to represent.

**AFTER**
> Two of the four encoded variants are, counter-intuitively, easier to detect than plain text: Base64-encoded semantic camouflage attacks are detected at $100.0\%$ and zero-width-character variants at $84.3\%$, because the act of encoding is itself a strong structural signal independent of the underlying intent. The plain-text form, detected at only $18.2\%$, is the case the category is designed to represent --- an ordinary-sounding academic or creative question with no encoding, no injected instruction, and no structural anomaly. Homoglyph substitution is the one variant that inverts this pattern, at $8.2\%$: it is detected \emph{worse} than the attack it disguises. That inversion is not explained by camouflage, and tracing it identified a concrete defect in the normalisation table, reported in Section~\ref{sec:future_work}.

### E16 — Ch4 Table `tab:sc_examples` · two wrong bypass mechanisms
All three queries were re-run: all three do clear L0–L3, so the examples are valid.
The stated mechanisms are not. The third query contains no non-ASCII character at all,
so it cannot involve homoglyph substitution. The second scores 19.0 and is classified
MEDIUM by L0 — a real structural signal, merely below the 30.0 blocking bar.

**BEFORE** (right-hand column, rows 2 and 3)
> Context-wrap framing; no structural anomalies
>
> Research framing combined with homoglyph substitution; anomaly score below threshold

**AFTER**
> Context-wrap framing; anomaly score 19.0, classified MEDIUM by L0 but below the 30.0 blocking bar
>
> Research framing; anomaly score 9.0, far below the 30.0 blocking bar

### E17 — Ch3 §3.3.3 (`subsec:l2`) and §3.6 (`sec:ch3summary`) · eight vs nine patterns
`rule_filter.py`'s `ALL_TIERS` defines nine tiers. Appendix~A lists nine. Chapter~3
describes eight and omits `output_hijack`.

**BEFORE** — add after Pattern 8 in §3.3.3:
> *(nothing — Pattern 9 is absent)*

**AFTER** — insert this paragraph after Pattern 8:
> \textbf{Pattern 9 --- Indirect output-hijack instructions.} Queries that do not attack the system's rules at all but instruct it to substitute a different task for the user's actual question --- for example, directing it to answer an unrelated question or produce unrelated content in place of the requested answer.

**BEFORE** — §3.6:
> L2 matches the sanitized query against eight structural attack patterns using regular expressions.

**AFTER**
> L2 matches the sanitized query against nine structural attack patterns using regular expressions.

### E18 — Ch4 Table `tab:layer_results`, note line
The 232 is not a "generic boundary-violation" family. It is the sum of five distinct
tiers that share the generic `rules` log key because they have no dedicated message:
context poisoning 66, authority impersonation 60, nested hiding 53, trust escalation
46, indirect authorization 7.

**BEFORE**
> Within L2, the four contributing pattern families were: direct injection (329), generic boundary-violation patterns (232), prompt extraction (155), and role redefinition (4).

**AFTER**
> Within L2, the contributing pattern tiers were: direct injection (329), prompt extraction (155), context poisoning (66), authority impersonation (60), nested hiding (53), trust escalation (46), indirect authorization (7), and role redefinition (4). The five middle tiers share a single generic log key, which is why they appear as one aggregate of 232 in the raw evaluation log.

---

## PART 4 — LATEX FAULTS

### E19 — Ch1 §1.6 (`sec:contributions`), fourth contribution — **compiles without error and destroys the paragraph**
Three unbalanced `$`. Test-compiled: LaTeX reports no error, and the sentence renders
as `90.23%−−−reducingthemeanattacksuccessratefrom` in italic maths on its own line,
with the remaining text reflowed around it.

**BEFORE**
> The fourth is the empirical demonstration that a mean detection rate of $90.23\%---reducing the mean attack success rate from $100\% to $9.77\%,(\pm\,1.08\%)$ across five independent runs---is achievable with a mean false positive rate of $0.12\%,(\pm\,0.16\%)$ across 333 legitimate queries per run.

**AFTER**
> The fourth is the empirical demonstration that a mean detection rate of 90.23\,\% --- reducing the mean attack success rate from 100\,\% to 9.77\,\% ($\pm$1.08\,\%) across five independent runs --- is achievable with a mean false positive rate of 0.12\,\% ($\pm$0.16\,\%) across 333 legitimate queries per run.

### E20 — Ch4 §4.3 (`sec:dataset`) — stray Markdown fence
A Markdown code fence sits in the `.tex` source immediately before
`\begin{table}[H]` for `tab:dataset_breakdown`. LaTeX will typeset the literal text
and the backticks become open-quote glyphs.

**BEFORE**
> ```latex
> \begin{table}[H]

**AFTER**
> \begin{table}[H]

*(Delete the fence line entirely. Check that no matching closing fence remains further down.)*

### E21 — Ch2 Table `tab:defense_comparison` — footnote (e) outside its group
Footnote (e) sits after the `}` that closes `{\footnotesize ...}`, so it renders at
body size while (a)–(d) are small.

**BEFORE**
> 		\textsuperscript{d}~Chen et al.\ report ASR approaching zero in certain scenarios; no single aggregate figure is provided across all evaluation conditions.}
> 		\textsuperscript{e}~The figures reported here for SecureRAG are from attacks the author generated for this thesis. A separate evaluation using an independently published benchmark (not created by the author) is reported in Chapter~\ref{ch:evaluation}.

**AFTER**
> 		\textsuperscript{d}~Chen et al.\ report ASR approaching zero in certain scenarios; no single aggregate figure is provided across all evaluation conditions.\\
> 		\textsuperscript{e}~The figures reported here for SecureRAG are from attacks the author generated for this thesis. A separate evaluation using an independently published benchmark (not created by the author) is reported in Chapter~\ref{ch:evaluation}.}

### E22 — Ch4 Table `tab:cross_model_internal` — column count
Four columns declared, three used; an empty column is typeset on the right.

**BEFORE**
> 	\begin{tabular}{lccc}

**AFTER**
> 	\begin{tabular}{lcc}

### E23 — Global · `\%,(\pm` renders as `%,(±`
A comma is standing where a thin space belongs. It occurs in Ch1 §1.1 and §1.6,
Ch3 §3.3.1 and §3.5, Ch4 §4.7, and Ch5 §5.2 and §5.3.

**BEFORE**
> 0.12\%,($\pm$0.16\%)

**AFTER**
> 0.12\,\% ($\pm$0.16\,\%)

---

## PART 5 — STALE FRAMING (the FPR is no longer zero)

### E24 — Ch2 §2.6 (`sec:research_gaps`), Gap 2
**BEFORE**
> To the best of the author's knowledge, no published work in the prompt injection literature reports a system that simultaneously achieves strong attack detection and a zero false positive rate.

**AFTER**
> To the best of the author's knowledge, no published work in the prompt injection literature reports a system that simultaneously achieves strong attack detection and a false positive rate below one percent on an explicitly measured benign set.

### E25 — Ch5 §5.2 (`sec:contributions_summary`), opening paragraph
**BEFORE**
> the published literature had not produced a defense that simultaneously achieves high attack detection, zero false positives, and full local deployment without reliance on external APIs

**AFTER**
> the published literature had not produced a defense that simultaneously achieves high attack detection, an explicitly measured and sub-one-percent false positive rate, and full local deployment without reliance on external APIs

### E26 — Ch3 Table `tab:attack_distribution` — the "Weight" column is mislabeled
The values in that column are measured shares, not the generator's tier weights. The
two differ where it matters: nested hiding is weighted 13 % and listed as 12.5 %;
conversational drift is weighted 10 % and listed as 9.3 %. The counts themselves were
re-measured across all five seeds and are **exactly correct** — only the header and
the two weights need changing.

**BEFORE** (header, then the two affected rows)
> \textbf{Weight} & \textbf{Queries (mean $\pm$ std)}
> Nested instruction hiding  & Commands embedded inside legitimate tasks         & 12.5\% & 125.4 $\pm$ 11.3 \\
> Conversational drift       & Gradual boundary erosion via friendly dialogue    & 9.3\% & 93.0 $\pm$ 6.8 \\

**AFTER**
> \textbf{Tier weight} & \textbf{Queries (mean $\pm$ std)}
> Nested instruction hiding  & Commands embedded inside legitimate tasks         & 13\% & 125.4 $\pm$ 11.3 \\
> Conversational drift       & Gradual boundary erosion via friendly dialogue    & 10\% & 93.0 $\pm$ 6.8 \\

*(The other six rows' weights already match the generator: context poisoning 15 %,
indirect poisoning 15 %, token smuggling 13 %, semantic camouflage 12 %,
psychological manipulation 12 %, trust escalation 10 %. Round those six to whole
numbers for consistency. The "Total 100 %" line stays.)*

### E27 — Ch3 §3.3.4 (`subsec:l3`) — grammar
**BEFORE**
> The layer computes an anomaly score by analyses six dimensions.

**AFTER**
> The layer computes an anomaly score by analysing six dimensions.

---

## PART 6 — ADDITIONS (threshold justification)

### E28 — Insert the new section
Add `\input{THRESHOLDS_SECTION.tex}` at the end of Chapter~3, after §3.5
(`sec:boundaries`) and before the chapter summary. It becomes §3.6 and supplies:
a table of all four numeric parameters with the basis for each; the L3 sweep
(Table~\ref{tab:l3_sweep}); the L4 threshold's full history; the L0 statement that
replaces E2; the retrieval-threshold disclosure that replaces E1; and the tuning-set
circularity disclosure with the 1.20 % held-out figure.

Re-label the existing §3.6 summary as §3.7.

### E29 — Ch3 §3.3.4 (`subsec:l3`), final paragraph — state the value and point to the sweep
**BEFORE**
> A query exceeding the blocking threshold---which is lowered for HIGH-risk queries identified by L0---is blocked before proceeding to retrieval.

**AFTER**
> A query exceeding the blocking threshold is blocked before proceeding to retrieval. The bar is twice the effective anomaly threshold, where the effective threshold is reduced to $0.7\times$ its nominal value of $15.0$ for queries L0 has classified HIGH --- so the bar is $30.0$ for LOW and MEDIUM queries and $21.0$ for HIGH ones. Section~\ref{subsec:l3_threshold} reports the sweep from which the value $15.0$ was selected, and identifies $17.5$ as a defensible alternative that the sweep does not rule out.

### E30 — Ch3 §3.3.5 (`subsec:l4`) — point to the L4 sweep
**BEFORE**
> A similarity score below the semantic threshold of $0.18$ causes the response to be suppressed and an error message to be returned to the user.

**AFTER**
> A similarity score below the semantic threshold of $0.18$ causes the response to be suppressed and an error message to be returned to the user. Section~\ref{subsec:l4_threshold} reports how that value was selected, including the two earlier values it replaced and the two-sided sweep that bounds it.

---

## VERIFIED CORRECT — no change needed

Checked and confirmed against the code or a measurement run:

| Claim | Status |
|---|---|
| Category counts, all eight rows, mean $\pm$ std over 5 seeds | exact |
| Obfuscation shares 12.73 / 9.27 / 8.87 / 4.88 / 64.26 % over n=5{,}005 | exact |
| Designed obfuscation weights 12 / 10 / 8 / 5 / 65 % | match the code |
| Layer table 158 / 720 / 24 / 10 = 912, and 17.3 / 78.9 / 2.6 / 1.1 % | exact |
| 98.9 % blocked before inference — $902/912$ | exact |
| Latency reduction 61.3 % — $17.837 \rightarrow 6.896$\,s | exact |
| Blocked mean $903.2 \pm 10.8$ over 5 seeds | exact |
| Ablation 100 / 84.22 / 12.29 / 9.89 %, latencies 17.84 / 16.74 / 7.96 / 6.67\,s | exact |
| L4 on seed 42: $902 \rightarrow 912$, ASR $9.89 \rightarrow 8.89$ % | exact |
| Wilson FPR $[0.05\%, 1.68\%]$ for 1/333 | recomputed, exact |
| Wilson ASR $[8.1\%, 11.8\%]$ for 9.77 % of 1{,}001 | recomputed, exact |
| McNemar $\chi^2 = 901.0$ from $(903-1)^2/903$ | recomputed, exact |
| Per-category DR table, all eight rows | matches the run |
| "Six of eight above 90 %, four at or above 98 %" | correct against the table |
| SC variant table 91 / 51 / 27 / 384 / 49, summing to 602 | exact |
| All three `tab:sc_examples` queries do clear L0–L3 | re-run, confirmed |
| External: 420 / 398 / 11 / 157 = 986; 84.08 %; 3.6$\times$; 70.3 % | exact |
| External FPR 1.80 % (6/333), all at L3 | exact, and reproduced by the L3 sweep |
| Nine of 29 categories, 31 % of categories, 77.1 % of compliances | exact |
| Cross-model table, both sides, all rows | matches the run |
| Llama precision 70 % on extra L4 firings — $32/46$ | exact |
| Homoglyph patch 73.9 $\rightarrow$ 88.1 %, overall 89.37 $\rightarrow$ 90.63 % | matches the patch record |
| Appendix A line counts, pattern tiers, gating conditions | match the source |
| Appendix B, all fifteen attributions | re-measured this session |
