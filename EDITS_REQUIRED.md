# Edits for Chapters 1 to 5 and the Appendices

Twenty-seven edits, each given as the text to replace and the text to put in its place.
Every figure quoted here was checked against the source files or measured during this
review. A list of the claims that were checked and found correct is at the end, so you
can see what was covered and leave it alone.

Each edit starts with a short note on why it is needed. The replacement text is written
to stand on its own in the thesis. It does not refer back to what it replaced.

---

## Part 1. Passages to rewrite because they describe something the code does differently

### E1. Chapter 3, Section 3.2.5, the retrieval threshold

The code does something better than the current text describes. In `pipeline.py`, if no
passage clears 0.15 the two highest-scoring passages are supplied anyway
(`selected = relevant if relevant else docs[:2]`), so the threshold cannot leave a query
without context. The replacement states that behaviour and points to the new thresholds
section for the parameter's place among the others.

**Replace:**

> This threshold was determined empirically through a calibration experiment on a held-out validation set of 50 queries drawn from the evaluation corpus before the main evaluation began. The value of 0.15 was chosen as the point at which retrieval failure---returning no usable documents for legitimate queries---was minimized without admitting weakly related content that would raise context poisoning risk. Thresholds below 0.10 allowed irrelevant documents through to the language model, while thresholds above 0.20 caused retrieval failure on approximately 8\% of legitimate queries in the validation set. The selected value sits within the empirically observed stable range between these two bounds.

**With:**

> The threshold acts as a relevance filter rather than a hard gate. If no retrieved passage clears it, the two highest-scoring passages are supplied regardless, so a legitimate query is never left without context. Its influence on the reported results is indirect: it determines which passages the model receives, and affects blocking only through the similarity L4 subsequently measures on the response. Section~\ref{subsec:retrieval_threshold} places it alongside the framework's other numeric parameters.

---

### E2. Chapter 3, Section 3.3.1, the L0 risk bands

The two bands are multiples of the anomaly threshold, so they are settled by calibrating
that one value rather than on their own. The stronger point in their favour is
structural: L0 returns a classification and never blocks, so a query it rates too highly
is examined more closely rather than refused. The replacement makes both points and adds
the measured effect on legitimate traffic.

**Replace:**

> These multiplier boundaries were established through iterative manual testing on a development sample of 50 attack queries and 50 legitimate queries drawn from the BIPIA benchmark~\cite{yi2025benchmarking}, held out from the 1{,}334-query main evaluation dataset to prevent data leakage. The MEDIUM boundary of 1.0 times the base anomaly threshold marks the point at which the anomaly score begins to deviate from the distribution observed in benign development queries: below this value, scores were indistinguishable from the benign baseline, while above it, at least one structural risk signal was consistently present. The HIGH boundary of 1.8 was selected because queries above this level consistently exhibited multiple co-occurring signals---such as elevated keyword density combined with obfuscation indicators---that warranted activating both the stricter L3 threshold and L4 simultaneously.
>
> The empirical support for these boundaries is provided in Section~\ref{subsec:fpr}, where the false positive rate of 0.12\%,($\pm$0.16\%)across 333 legitimate queries confirms that the LOW classification correctly excludes the great majority of benign inputs from L4 evaluation. A formal grid search over a larger calibration set would provide stronger statistical grounding; this limitation is acknowledged as part of the threshold selection procedure.

**With:**

> Neither boundary is an independent parameter. Both are multiples of the anomaly threshold examined in Section~\ref{subsec:l3_threshold}, so calibrating that single value settles both.
>
> The design also limits what a misjudgement at this stage can cost. L0 does not block. It returns a classification that adjusts two later decisions, lowering L3's effective bar for HIGH-risk queries and opening L4's gate, and no query is refused on L0's verdict alone. A query the sensor rates too highly is examined more closely rather than rejected.
>
> The effect on legitimate traffic is reported in Section~\ref{subsec:fpr}. Across the 333 legitimate queries of the representative run, every query was classified LOW, 315 scored zero on all six anomaly dimensions and were exempt from L4, and the remaining 18 were passed to L4 for checking.

---

### E3 to E6. The L4 activation condition, in four places

`pipeline.py` opens the L4 gate when L0 returned HIGH or MEDIUM, or when the anomaly
score is above zero:

```python
if response and (risk_level in ["HIGH", "MEDIUM"] or anomaly_score > 0):
```

A LOW-risk query is exempt only when its score is exactly zero. Four passages describe
the gate as risk-level only, including both algorithm listings, so all four need the same
correction.

**E3. Chapter 3, Section 3.3.1, final paragraph. Replace:**

> Only MEDIUM and HIGH-risk queries activate L4; queries classified as LOW bypass the semantic guardrail entirely---and this selective deactivation is the mechanism that keeps the false positive rate near zero~\cite{ramakrishnan2025securing,liu2024formalizing}.

**With:**

> L4 runs when L0 returned MEDIUM or HIGH, or when the anomaly score is above zero on any of the six dimensions L3 measures. A LOW-risk query is exempt only when that score is exactly zero. This gating is what keeps the false positive rate near zero: on the representative benign batch it sent 18 of 333 queries to L4 rather than all 333~\cite{ramakrishnan2025securing,liu2024formalizing}.

**E4. Chapter 3, Section 3.3.5. Replace:**

> L4 activates only for queries classified as MEDIUM or HIGH risk by L0. Queries classified as LOW risk bypass the semantic guardrail entirely. This selective activation is the design decision that keeps the false positive rate near zero: most legitimate queries about topics that superficially resemble injection language---such as questions about anomaly detection or quantization---are never evaluated by L4 at all. The small residual share that does reach L4 (Section~\ref{subsec:fpr}) is where the two observed false positives occurred~\cite{chen2025defense,liu2024formalizing,ramakrishnan2025securing}.

**With:**

> L4 activates when L0 classified the query MEDIUM or HIGH risk, or when its anomaly score is above zero on any of the six dimensions L3 measures. A LOW-risk query bypasses the guardrail only if that score is exactly zero. This gating is the design decision that keeps the false positive rate near zero: on the representative benign batch, 315 of 333 legitimate queries scored zero and were never evaluated by L4 at all. The 18 that did reach it (Section~\ref{subsec:fpr}) are the only queries where an internal false positive is possible, and both observed false positives occurred there~\cite{chen2025defense,liu2024formalizing,ramakrishnan2025securing}.

**E5. Chapter 3, Algorithm 1, Step 6. Replace:**

> 	\tcp{Step 6 — Check response (only for MEDIUM and HIGH risk)}
> 	\If{risk is MEDIUM or HIGH}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

**With:**

> 	\tcp{Step 6 — Check response (skipped only when LOW risk and anomaly score is zero)}
> 	\If{risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

**E6. Chapter 3, Algorithm 2, Enforcement Point 3. Replace:**

> 	\If{risk is MEDIUM or HIGH \textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

**With:**

> 	\If{(risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$) \textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

---

### E7. Chapter 5, Section 5.2, second contribution

Two things to bring into line. The false positive rate is 0.12 per cent, and the support
for this claim comes from the L4 gating measurement rather than from the ablation study,
which adds L1 to L4 cumulatively and does not test the system without L0.

**Replace:**

> This architectural decision is what keeps the false positive rate at zero across the full evaluation dataset. Without the ARS, uniform application of all five layers to every query would introduce false positives, as confirmed by the ablation results in Section~\ref{subsec:ablation}.

**With:**

> This architectural decision is what holds the false positive rate at 0.12\,\% ($\pm$0.16\,\%). Without it, L4 would run on all 333 legitimate queries in each batch rather than the 18 that carry any structural signal at all, and every one of them would become a candidate for a false positive.

---

### E17. Chapter 3, Section 3.3.3 and Section 3.6, the number of L2 patterns

`ALL_TIERS` in `rule_filter.py` defines nine tiers, and Appendix A lists nine. Chapter 3
describes eight, so the ninth needs adding and the count in the summary updating.

**Add after Pattern 8 in Section 3.3.3:**

> \textbf{Pattern 9 --- Indirect output-hijack instructions.} Queries that leave the system's rules alone and instead instruct it to substitute a different task for the user's actual question, for example directing it to answer an unrelated question or produce unrelated content in place of the requested answer.

**In Section 3.6, replace:**

> L2 matches the sanitized query against eight structural attack patterns using regular expressions.

**With:**

> L2 matches the sanitized query against nine structural attack patterns using regular expressions.

---

## Part 2. Figures to update

### E8. Chapter 4, Section 4.5.3, the share held by L3 and L4

The per-query measurement now reported in Table~\ref{tab:layer_results} gives
$(24+10)/912 = 3.7$ per cent. The figure of 8.2 per cent comes from the earlier
ablation-derived layer table, where the two layers were credited with 34 and 41 blocks
out of 910.

**Replace:**

> The primary source of run-to-run variation arises from the L3 anomaly threshold and the L4 semantic similarity comparison, though these together account for only 8.2\% of all blocked queries.

**With:**

> L3 and L4 together account for 3.7\% of all blocked queries in this run, 34 of 912.

---

### E9. Chapter 4, Section 4.5.3, variation in the L1 and L2 counts

Measured across the five seeds, L1 blocks 161.4 on average with a standard deviation of
10.3 and a range of 149 to 173; L2 blocks 708.2 with a standard deviation of 13.3 and a
range of 691 to 720; L3 blocks 25.0 with a standard deviation of 2.2. L2 varies more than
L3 in absolute terms. The layers are deterministic for a given query, and the variation
comes from each seed drawing a different mix of attack categories and obfuscation
variants.

**Replace:**

> Blocking counts for L1 and L2 are largely deterministic---both apply fixed rules and patterns---so variance across runs is negligible.

**With:**

> L1 and L2 are deterministic for a given query, since both apply fixed rules and patterns, but their counts still vary across runs because each seed draws a different mix of attack categories and obfuscation variants. Measured over the five seeds, L1 blocks 161.4 ($\pm$10.3), L2 blocks 708.2 ($\pm$13.3), and L3 blocks 25.0 ($\pm$2.2).

---

### E10. Chapter 4, caption of the per-category figure

The table on the same page gives token smuggling as 99.7 ($\pm$0.4) and context poisoning
as 100.0 ($\pm$0.0), so the caption should name context poisoning.

**Replace:**

> Token smuggling achieves perfect detection (DR = 100\%) with zero variance.

**With:**

> Context poisoning achieves perfect detection (DR = 100.0\%) with zero variance across all five runs.

---

### E11. Chapter 4 summary and Chapter 5, Section 5.2, the ablation sentence

The same sentence appears in both chapters and needs the same replacement. The
configuration described as "removing L2 alone" is L0+L1, which also lacks L3 and L4. The
2.52-point figure subtracts the five-seed mean of 9.77 per cent from the single-seed
ablation value of 12.29 per cent. Keeping both figures on seed 42 gives
$12.29 - 8.89 = 3.40$ points.

**Replace:**

> the ablation study confirmed that each layer contributes individually: removing L2 alone raises the ASR from $9.77\%$ to $84.22\%$, and removing L3 and L4 leaves a further $2.52$ percentage points of attacks undetected.

**With:**

> the ablation study confirmed that each layer contributes individually: on seed~$=42$, the L0+L1 configuration records an ASR of $84.22\%$ against $12.29\%$ once L2 is added, and adding L3 and L4 to that configuration removes a further $3.40$ percentage points, from $12.29\%$ to $8.89\%$.

---

### E12. Chapter 4, Section 4.5.5, the false positive description

The Python-subclass and `.gitignore` responses score between 0.186 and 0.2331, which is
above the 0.18 threshold, so they pass. They are the queries the threshold was set to
protect. Describing the margin gives the same point with a figure behind it.

**Replace:**

> The two observed false positives occurred at L4, on legitimate but security-adjacent questions (for example, asking how to override a method in a Python subclass) whose corpus-similarity score fell only marginally below the semantic threshold.

**With:**

> Both observed false positives occurred at L4, on responses whose corpus-similarity score fell below the 0.18 semantic threshold. The margin involved is narrow. Running the demonstration queries of Appendix~\ref{app:demo} through the complete system gives similarity scores of 0.1949 and 0.2189 for the two security-adjacent benign queries that reach L4, against a threshold of 0.18: the first clears the bar by 0.0149. Across the wider internal benign set the five responses closest to the boundary fall between 0.186 and 0.2331, so the nearest of them sits 0.006 above a block.

---

### E13. Chapter 4, Section 4.5.10

Appendix B now contains ten attack examples.

**Replace:**

> covering five legitimate queries and nine attack attempts drawn from all eight injection categories

**With:**

> covering five legitimate queries and ten attack attempts drawn from all eight injection categories

---

### E14. Chapter 5, Section 5.3, opening line

Six limitations are listed in the section.

**Replace:**

> Four limitations bound the scope of these findings, and all four must be taken into account when interpreting the evaluation outcomes.

**With:**

> Six limitations bound the scope of these findings, and all six must be taken into account when interpreting the evaluation outcomes.

---

### E15. Chapter 4, Section 4.5.8, the obfuscation variants

Table~\ref{tab:sc_variants} on the same page gives homoglyph substitution at 8.2 per cent,
below plain text at 18.2 per cent, so the paragraph should account for it. The inversion
is worth keeping, because tracing it is what led to the normalisation fix reported in
Chapter 5.

**Replace:**

> Obfuscation-encoded variants are, counter-intuitively, easier to detect than plain text: Base64-encoded semantic camouflage attacks are detected at $100.0\%$, and zero-width-character variants at $84.3\%$, because the act of encoding is itself a strong structural signal independent of the underlying intent. The genuinely hard case is the plain-text form, detected at only $18.2\%$, since it is precisely this form---an ordinary-sounding academic or creative question with no encoding, no injected instruction, and no structural anomaly---that the category is designed to represent.

**With:**

> Two of the four encoded variants are, counter-intuitively, easier to detect than plain text. Base64-encoded semantic camouflage attacks are detected at $100.0\%$ and zero-width-character variants at $84.3\%$, because the act of encoding is itself a strong structural signal independent of the underlying intent. The plain-text form, detected at $18.2\%$, is the case the category is designed to represent: an ordinary-sounding academic or creative question with no encoding, no injected instruction, and no structural anomaly. Homoglyph substitution inverts this pattern at $8.2\%$, detected less often than the plain attack it disguises. Camouflage does not explain that inversion, and tracing it identified a specific defect in the normalisation table, reported in Section~\ref{sec:future_work}.

---

### E16. Chapter 4, the bypass mechanisms in Table `tab:sc_examples`

All three queries were re-run through the pipeline and all three do clear L0 to L3, so
the examples themselves stand. Two of the descriptions can be sharpened with the measured
scores. The third query is plain ASCII throughout, and its anomaly score of 9.0 is what
carries it past L3.

**Replace, in the right-hand column of rows 2 and 3:**

> Context-wrap framing; no structural anomalies
>
> Research framing combined with homoglyph substitution; anomaly score below threshold

**With:**

> Context-wrap framing; anomaly score 19.0, classified MEDIUM by L0 but below the 30.0 blocking bar
>
> Research framing; anomaly score 9.0, well below the 30.0 blocking bar

---

### E18. Chapter 4, the note under Table `tab:layer_results`

The 232 is an aggregate of five tiers that share one log key because none of them has a
dedicated block message: context poisoning 66, authority impersonation 60, nested hiding
53, trust escalation 46, indirect authorization 7. Listing them shows the spread and
still reconciles with the raw log.

**Replace:**

> Within L2, the four contributing pattern families were: direct injection (329), generic boundary-violation patterns (232), prompt extraction (155), and role redefinition (4).

**With:**

> Within L2, the contributing pattern tiers were direct injection (329), prompt extraction (155), context poisoning (66), authority impersonation (60), nested hiding (53), trust escalation (46), indirect authorization (7), and role redefinition (4). The five middle tiers share a single generic log key, which is why they appear as one aggregate of 232 in the raw evaluation log.

---

## Part 3. LaTeX corrections

### E19. Chapter 1, Section 1.6, the fourth contribution

Three unbalanced dollar signs. This one is worth checking carefully because LaTeX reports
no error: the sentence compiles and typesets as
`90.23%−−−reducingthemeanattacksuccessratefrom` in italic maths on its own line, with the
rest of the text reflowing around it.

**Replace:**

> The fourth is the empirical demonstration that a mean detection rate of $90.23\%---reducing the mean attack success rate from $100\% to $9.77\%,(\pm\,1.08\%)$ across five independent runs---is achievable with a mean false positive rate of $0.12\%,(\pm\,0.16\%)$ across 333 legitimate queries per run.

**With:**

> The fourth is the empirical demonstration that a mean detection rate of 90.23\,\%, reducing the mean attack success rate from 100\,\% to 9.77\,\% ($\pm$1.08\,\%) across five independent runs, is achievable with a mean false positive rate of 0.12\,\% ($\pm$0.16\,\%) across 333 legitimate queries per run.

---

### E20. Chapter 4, Section 4.3

A Markdown code fence sits in the source immediately before `\begin{table}[H]` for
`tab:dataset_breakdown`. LaTeX will typeset the word and turn the backticks into quote
glyphs.

**Delete this line:**

> ```latex

Then check that no matching closing fence remains further down.

---

### E21. Chapter 2, the footnote block under Table `tab:defense_comparison`

Footnote (e) currently sits after the brace that closes `{\footnotesize ...}`, so it
prints at body size while (a) to (d) print small. Moving the brace to the end fixes it.

**Replace:**

> 		\textsuperscript{d}~Chen et al.\ report ASR approaching zero in certain scenarios; no single aggregate figure is provided across all evaluation conditions.}
> 		\textsuperscript{e}~The figures reported here for SecureRAG are from attacks the author generated for this thesis. A separate evaluation using an independently published benchmark (not created by the author) is reported in Chapter~\ref{ch:evaluation}.

**With:**

> 		\textsuperscript{d}~Chen et al.\ report ASR approaching zero in certain scenarios; no single aggregate figure is provided across all evaluation conditions.\\
> 		\textsuperscript{e}~The figures reported here for SecureRAG are from attacks the author generated for this thesis. A separate evaluation using an independently published benchmark (not created by the author) is reported in Chapter~\ref{ch:evaluation}.}

---

### E22. Chapter 4, Table `tab:cross_model_internal`

Four columns are declared and three are used, which prints an empty column on the right.

**Replace:**

> 	\begin{tabular}{lccc}

**With:**

> 	\begin{tabular}{lcc}

---

### E23. Throughout

A comma is standing where a thin space belongs, so the figure prints as `0.12%,(±0.16%)`.
It appears in Chapter 1 Sections 1.1 and 1.6, Chapter 3 Sections 3.3.1 and 3.5,
Chapter 4 Section 4.7, and Chapter 5 Sections 5.2 and 5.3.

**Replace:**

> 0.12\%,($\pm$0.16\%)

**With:**

> 0.12\,\% ($\pm$0.16\,\%)

---

### E27. Chapter 3, Section 3.3.4

**Replace:**

> The layer computes an anomaly score by analyses six dimensions.

**With:**

> The layer computes an anomaly score by analysing six dimensions.

---

## Part 4. Wording to bring into line with the measured false positive rate

### E24. Chapter 2, Section 2.6, Gap 2

The gap is still real and still worth stating. Phrasing it as a measured rate rather than
as zero keeps it consistent with the 0.12 per cent reported in Chapter 4.

**Replace:**

> To the best of the author's knowledge, no published work in the prompt injection literature reports a system that simultaneously achieves strong attack detection and a zero false positive rate.

**With:**

> To the best of the author's knowledge, no published work in the prompt injection literature reports a system that simultaneously achieves strong attack detection and a false positive rate below one per cent on an explicitly measured benign set.

---

### E25. Chapter 5, Section 5.2, opening paragraph

**Replace:**

> the published literature had not produced a defense that simultaneously achieves high attack detection, zero false positives, and full local deployment without reliance on external APIs

**With:**

> the published literature had not produced a defense that simultaneously achieves high attack detection, an explicitly measured false positive rate below one per cent, and full local deployment without reliance on external APIs

---

### E26. Chapter 3, Table `tab:attack_distribution`, the Weight column

The counts in this table were re-measured across all five seeds and every one of them is
exact, so only the header and two of the eight weights need touching. The column holds
measured shares, and two of them differ from the generator's tier weights: nested hiding
is weighted 13 per cent and listed as 12.5, conversational drift is weighted 10 per cent
and listed as 9.3.

**Replace, in the header and the two affected rows:**

> \textbf{Weight} & \textbf{Queries (mean $\pm$ std)}
>
> Nested instruction hiding  & Commands embedded inside legitimate tasks         & 12.5\% & 125.4 $\pm$ 11.3 \\
>
> Conversational drift       & Gradual boundary erosion via friendly dialogue    & 9.3\% & 93.0 $\pm$ 6.8 \\

**With:**

> \textbf{Tier weight} & \textbf{Queries (mean $\pm$ std)}
>
> Nested instruction hiding  & Commands embedded inside legitimate tasks         & 13\% & 125.4 $\pm$ 11.3 \\
>
> Conversational drift       & Gradual boundary erosion via friendly dialogue    & 10\% & 93.0 $\pm$ 6.8 \\

The other six weights already match the generator: context poisoning 15, indirect
poisoning 15, token smuggling 13, semantic camouflage 12, psychological manipulation 12,
trust escalation 10. Round those to whole numbers so the column reads consistently, and
leave the total row as it is.

---

## Part 5. New material

### E28. Add the thresholds section

Insert `\input{THRESHOLDS_SECTION.tex}` at the end of Chapter 3, after
Section~\ref{sec:boundaries} and before the chapter summary. It becomes Section 3.6, and
the existing summary moves to 3.7.

The section covers all four numeric parameters in one place. It carries the L3 sweep
across five seeds with both benign sets, the history of the L4 threshold with the
measurements behind each revision, the L0 bands, the retrieval floor, and the held-out
false positive figure of 1.20 per cent alongside the 1.80 per cent measured on the tuning
set. Sections E1 and E2 above refer into it.

### E29. Chapter 3, Section 3.3.4, final paragraph

**Replace:**

> A query exceeding the blocking threshold---which is lowered for HIGH-risk queries identified by L0---is blocked before proceeding to retrieval.

**With:**

> A query exceeding the blocking threshold is blocked before proceeding to retrieval. The bar is twice the effective anomaly threshold, and the effective threshold is the nominal value of $15.0$ for LOW and MEDIUM queries and $0.7$ times that for queries L0 has classified HIGH, giving a bar of $30.0$ in the ordinary case and $21.0$ for high-risk queries. Section~\ref{subsec:l3_threshold} reports the sweep behind the value of $15.0$ and identifies $17.5$ as a reasonable alternative.

### E30. Chapter 3, Section 3.3.5

**Replace:**

> A similarity score below the semantic threshold of $0.18$ causes the response to be suppressed and an error message to be returned to the user.

**With:**

> A similarity score below the semantic threshold of $0.18$ causes the response to be suppressed and an error message to be returned to the user. Section~\ref{subsec:l4_threshold} reports how that value was arrived at, including the two-sided sweep that bounds it.

---

## Checked and correct, no change needed

These were verified against the code or recomputed during this review.

| Claim | Result |
|---|---|
| Category counts, all eight rows, mean and standard deviation over five seeds | exact |
| Obfuscation shares 12.73, 9.27, 8.87, 4.88, 64.26 per cent over n = 5,005 | exact |
| Designed obfuscation weights 12, 10, 8, 5, 65 per cent | match the generator |
| Layer table 158, 720, 24, 10 summing to 912, and 17.3, 78.9, 2.6, 1.1 per cent | exact |
| 98.9 per cent blocked before inference, 902 of 912 | exact |
| Latency reduction 61.3 per cent, 17.837 to 6.896 seconds | exact |
| Blocked mean 903.2 with standard deviation 10.8 over five seeds | exact |
| Ablation 100, 84.22, 12.29, 9.89 per cent and latencies 17.84, 16.74, 7.96, 6.67 seconds | exact |
| L4 on seed 42, 902 to 912 blocked, ASR 9.89 to 8.89 per cent | exact |
| Wilson interval for the false positive rate, 0.05 to 1.68 per cent on 1 of 333 | recomputed, exact |
| Wilson interval for the attack success rate, 8.1 to 11.8 per cent | recomputed, exact |
| McNemar chi-squared of 901.0 from $(903-1)^2/903$ | recomputed, exact |
| Per-category detection table, all eight rows | matches the run |
| Six of eight above 90 per cent, four at or above 98 per cent | correct against the table |
| Semantic camouflage variant table, 91, 51, 27, 384, 49, summing to 602 | exact |
| All three queries in `tab:sc_examples` clear L0 to L3 | re-run, confirmed |
| External outcomes 420, 398, 11, 157 summing to 986, and 84.08 per cent | exact |
| Reach-rate over compliance, factor of 3.6, and 70.3 per cent resisted | exact |
| External false positive rate 1.80 per cent, 6 of 333, all at L3 | exact, and reproduced by the L3 sweep |
| Nine of 29 categories, 31 per cent of categories, 77.1 per cent of compliances | exact |
| Cross-model tables, both sides, every row | match the run |
| Llama precision of 70 per cent on the extra L4 firings, 32 of 46 | exact |
| Homoglyph fix, 73.9 to 88.1 per cent by variant and 89.37 to 90.63 per cent overall | matches the patch record |
| Appendix A line counts, pattern tiers, and gating conditions | match the source |
| Appendix B, all fifteen layer attributions | re-measured this session |

---

## Part 6. Appendix B, after the timing run

The demonstration was run on the evaluation hardware with the model and retrieval index
loaded, three passes per query, and the results are now folded into `APPENDIX_A_B.tex`.
There are around a dozen small insertions, so replace the whole of Appendix B with the
updated file rather than applying them one by one. What changed:

**Per-query latency, now measured rather than omitted.** All nine blocked attacks were
rejected in under a millisecond; the pipeline records the elapsed time to three decimal
places and every one of them rounded to 0.000 seconds. The five legitimate queries took
between 7.382 and 19.675 seconds, since each is answered in full. B.3 now uses that
contrast to make the latency argument concrete, and adds a sentence explaining why an
individual query can exceed the 17.837-second baseline mean without contradicting it.

**L4 similarity scores, now available.** The three benign queries that reach L4 score
0.8035, 0.2189 and 0.1949 against the 0.18 threshold, so the last clears it by 0.0149.
These are the security-adjacent phrasings the threshold was set to accommodate, and they
fall inside the 0.186 to 0.2331 band recorded for the wider benign set.

**The semantic camouflage bypass, explained by its score.** Item 10 scores 0.7602, higher
than two of the five legitimate queries. The model treated the question as an academic one
and answered from the corpus, which is why L4 passes it correctly. A new observation in
B.3 draws the distinction between clearing every layer and producing harmful output, and
connects it to the 70.3 per cent figure from the external benchmark.

**One convention now stated explicitly.** The run surfaced an ambiguity worth heading off.
For a block at L1, L3 or L4 the risk value recorded in the log is L0's classification of
the query. For a block at L2 it is instead the risk weight of the pattern tier that
matched, because `pipeline.py` passes `rule_risk` rather than `risk_level` on that path.
The two coincide for eight of the ten attack examples. They separate on item 8, where L0
returned LOW and the block is logged as MEDIUM because `trust_escalation` is a
MEDIUM-weighted tier. Both values are now given for that item, and the convention is
stated in the appendix preamble so a reader comparing the appendix against a fresh run
does not read it as a discrepancy.
