# Final Audit — full pass over Chapters 1 to 5, both abstracts, and the appendices

Twenty-one items. They are ordered by urgency, not by chapter, because eight of them
are places where two parts of the thesis now say different things. Those came from
edits landing in one location but not in the matching one, so the fix in each case is
to finish the change rather than to reconsider it.

A list of everything verified as correct and needing no attention is at the end.

---

## Part A. Contradictions currently live in the text

These eight are the ones to fix first. In each case the thesis states two different
things about the same fact, so a reader comparing two pages will find them disagreeing.

### A1. Algorithm 1, Step 6 — the comment and the condition disagree

The comment line was updated and the condition below it was not, so the algorithm now
reads as its own contradiction.

**Currently:**

> 	\tcp{Step 6 — Check response (skipped only when LOW risk and anomaly score is zero)}
> 	\If{risk is MEDIUM or HIGH}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

**Should be:**

> 	\tcp{Step 6 — Check response (skipped only when LOW risk and anomaly score is zero)}
> 	\If{risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$}{\If{response similarity to knowledge base $<$ threshold}{\Return BLOCKED (L4)\;}}

### A2. Chapter 5, Section 5.2 — the L4 gate, second contribution

The second sentence was updated and the first was not. As it stands the paragraph says
LOW-risk queries bypass L4 entirely and then, one line later, that 18 of them reach it.

**Currently:**

> Its most significant operational consequence is that legitimate queries classified as LOW risk bypass Layer L4 entirely. This architectural decision is what holds the false positive rate at 0.12\% ($\pm$0.16\%). Without it, L4 would run on all 333 legitimate queries in each batch rather than the 18 that carry any structural signal at all, and every one of them would become a candidate for a false positive.

**Should be:**

> Its most significant operational consequence is that a legitimate query is examined by Layer L4 only when it carries some structural signal, and is exempt when its anomaly score is zero across all six dimensions. This architectural decision is what holds the false positive rate at 0.12\,\% ($\pm$0.16\,\%). Without it, L4 would run on all 333 legitimate queries in each batch rather than the 18 that carry any signal at all, and every one of them would become a candidate for a false positive.

### A3. Chapter 5, Section 5.2 — the ablation figure, against Chapter 4's

Chapter 4 now gives 3.40 percentage points on seed 42. Chapter 5 still gives 2.52,
which comes from subtracting the five-seed mean of 9.77 from the seed-42 value of
12.29. The two chapters should quote the same number.

**Currently:**

> The ablation study confirms that each layer is individually necessary: removing L2 alone raises the ASR from 9.77\% to 84.22\%, and removing L3 and L4 together leaves a further 2.52 percentage points of attacks undetected.

**Should be:**

> The ablation study confirms that each layer is individually necessary: on seed~$=42$, the L0+L1 configuration records an ASR of 84.22\% against 12.29\% once L2 is added, and adding L3 and L4 to that configuration removes a further 3.40 percentage points, from 12.29\% to 8.89\%.

### A4. Chapter 5, Section 5.2 — the number of L2 patterns

Chapter 3 and Appendix A now both say nine. This sentence still says eight.

**Currently:**

> Layer L2 applies a library of regular-expression rules to detect eight known structural attack categories.

**Should be:**

> Layer L2 applies a library of regular-expression rules to detect nine known structural attack categories.

### A5. Both abstracts — the same count

The English abstract and the Arabic abstract each describe L2 as covering eight
categories, which no longer matches Chapter 3, Chapter 5 or Appendix A.

**English abstract, currently:**

> (L2) a rule-based structural detector that flags eight known attack categories

**Should be:**

> (L2) a rule-based structural detector that flags nine known attack categories

**Arabic abstract, currently:**

> وطبقة (L2) وهي المصفي القائم على القواعد الذي يكشف الأنماط الهيكلية لثمانية أنواع من الهجمات

**Should be:**

> وطبقة (L2) وهي المصفي القائم على القواعد الذي يكشف الأنماط الهيكلية لتسعة أنواع من الهجمات

### A6. Appendix B — the preamble promises something item 8 does not deliver

The preamble says item 8 gives both risk values. Item 8 gives only one. The measured
timing is also missing from this item while the other eight blocked attacks have it.

**Item 8 currently:**

> \textbf{[L0]} LOW risk. \textbf{[L1]} Passed. \textbf{[L2]} Pattern~7 match (\texttt{trust\_escalation}, MEDIUM). \textbf{Blocked at L2.} L0 classifying this LOW is by design: only the five HIGH-risk tiers feed the fast pre-screen, so a MEDIUM-risk tier is caught by the full filter rather than the sensor.

**Should be:**

> \textbf{[L0]} LOW risk. \textbf{[L1]} Passed. \textbf{[L2]} Pattern~7 match (\texttt{trust\_escalation}, weighted MEDIUM). \textbf{Blocked at L2 in under one millisecond.} L0 classifying this LOW is by design: only the five HIGH-risk tiers feed the fast pre-screen, so a MEDIUM-risk tier is caught by the full filter rather than the sensor. This is the item where the two risk values separate, per the convention noted above: L0 returned LOW, and the block is logged as MEDIUM because that is the weight of the tier that matched.

### A7. Chapter 4, Section 4.5.3 — the body paragraph against its own table note

The note under Table~\ref{tab:layer_results} now lists the eight tiers individually.
The paragraph after the figure still describes the 232 as one pattern family.

**Currently:**

> L2 blocked 720 attacks, or 78.9\% of all blocked queries---most of this share coming from direct-injection and generic boundary-violation patterns (329 and 232 respectively), with prompt-extraction patterns contributing a further 155.

**Should be:**

> L2 blocked 720 attacks, or 78.9\% of all blocked queries. Direct injection accounts for 329 of these and prompt extraction for a further 155, with the remaining 236 spread across six narrower tiers, as the note to Table~\ref{tab:layer_results} sets out.

### A8. Chapter 4, Section 4.3 — the stray code fence

A Markdown fence still sits immediately before `\begin{table}[H]` for
`tab:dataset_breakdown`. LaTeX will typeset the word `latex` and turn the backticks
into quotation glyphs.

**Delete this line entirely:**

> ```latex

---

## Part B. Edits from the previous list that have not yet landed

### B1. Chapter 4, Table `tab:cross_model_internal` — column count

Four columns are declared, three are used, so an empty column prints on the right.

**Currently:** `\begin{tabular}{lccc}`

**Should be:** `\begin{tabular}{lcc}`

### B2. The comma standing in for a thin space

This still appears in Chapter 1 Sections 1.1 and 1.6, Chapter 4 Section 4.6, and
Chapter 5 Section 5.3. It renders as `9.77%,(±1.08%)`.

**Replace every instance of** `9.77\%,($\pm$1.08\%)` **with** `9.77\,\% ($\pm$1.08\,\%)`

**Replace every instance of** `0.12\%,($\pm$0.16\%)` **with** `0.12\,\% ($\pm$0.16\,\%)`

**Replace** `59.1\%,($\pm$4.5\%)` **with** `59.1\,\% ($\pm$4.5\,\%)`

Chapter 1 Section 1.6 also carries a double space after the closing bracket; a single
space is enough.

### B3. Appendix A, Section A.3 — two scripts now cited but not listed

Chapter 3 Section 3.6 reports the L3 sweep and Appendix B reports the measured demo
timings. The scripts that produced both are missing from the list, which matters for
reproducibility since these are the only two results a reader cannot regenerate from
the listed scripts.

**Add two bullets:**

> 	\item \texttt{l3\_threshold\_sensitivity.py} --- the sweep of \texttt{ANOMALY\_THRESHOLD} across attacks and both benign sets reported in Section~\ref{subsec:l3_threshold}. It loads no language model.
> 	\item \texttt{run\_demo\_appendix.py} --- runs the fifteen queries of Appendix~\ref{app:demo} through the complete system to record per-query latency and L4 similarity.

---

## Part C. Found in this pass

### C1. Chapter 2 — five areas in the overview, four in the summary

Section 2.1 lists five: RAG origins, security risks, attack taxonomy, defenses, and
research gaps. The summary counts four.

**Currently:**

> This chapter reviewed the literature across four areas relevant to this research.

**Should be:**

> This chapter reviewed the literature across five areas relevant to this research.

### C2. Chapter 3, Section 3.1 — the roadmap skips the new section

The closing paragraph walks the reader through 3.2, 3.3, 3.4 and 3.5 and then jumps to
the summary, leaving 3.6 unannounced.

**Currently:**

> Section~\ref{sec:boundaries} examines the Dual-Channel System Boundaries Principle in depth. Section~\ref{sec:ch3summary} summarizes the principal design decisions.

**Should be:**

> Section~\ref{sec:boundaries} examines the Dual-Channel System Boundaries Principle in depth. Section~\ref{sec:thresholds} sets out the framework's four numeric parameters and the evidence behind each. Section~\ref{sec:ch3summary} summarizes the principal design decisions.

### C3. Chapter 3, Section 3.3.1 — the 18 of 333 figure appears twice

It is now stated once in the paragraph beginning "The effect on legitimate traffic"
and again three paragraphs later. Keep the first, which gives the fuller breakdown,
and shorten the second.

**Second instance currently:**

> This gating is what keeps the false positive rate near zero: on the representative benign batch it sent 18 of 333 queries to L4 rather than all 333~\cite{ramakrishnan2025securing,liu2024formalizing}.

**Should be:**

> This gating is what keeps the false positive rate near zero, since it reserves the output check for the small share of queries that show any structural signal at all~\cite{ramakrishnan2025securing,liu2024formalizing}.

### C4. Appendix B, item 5 of Section B.1 — the only query without its timing

Items 1 to 4 each end with a measured latency. Item 5 does not, and the run recorded
one.

**Add at the end of item 5:**

> \textbf{Latency 16.764\,s.}

### C5. Algorithm 2 — spacing and a safer comparison symbol

The condition currently reads `>0)\textbf{and}`, with no space, and uses a bare `>`.
Under the OT1 font encoding a bare `>` prints as an inverted question mark, so putting
it in maths mode removes the risk regardless of preamble.

**Currently:**

> 	\If{(risk is MEDIUM or HIGH \textbf{or} anomaly score >0)\textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

**Should be:**

> 	\If{(risk is MEDIUM or HIGH \textbf{or} anomaly score $>0$) \textbf{and} $sim <$ threshold}{\Return BLOCKED\;}

### C6. Chapter 4, Section 4.6 — literal plus-minus characters

Two figures in this paragraph use the typed character `±` rather than `$\pm$`. Under
some encodings it drops silently.

**Currently:**

> SecureRAG achieves a mean ASR of 9.77\%\,(±1.08\%) with FPR of 0.12\%,(±0.16\%)

**Should be:**

> SecureRAG achieves a mean ASR of 9.77\,\% ($\pm$1.08\,\%) with an FPR of 0.12\,\% ($\pm$0.16\,\%)

### C7. English abstract — a missing space

**Currently:**

> of 0.12\% ($\pm$0.16\%)across all 333 legitimate queries

**Should be:**

> of 0.12\,\% ($\pm$0.16\,\%) across all 333 legitimate queries

### C8. Appendix B, Section B.3 — a doubled command

`\medskip\noindent` appears twice in a row before the fourth observation. Delete one.

### C9. Chapter 4, Section 4.5.4 — a claim the numbers qualify

The closing sentence credits L4 as the primary interceptor of semantic camouflage.
Appendix B records that 71 such attacks reached L4 on seed 42 and that it blocked 10
of them, so L4 is the only layer positioned to catch them rather than the one catching
most of them. Naming the mechanism is the stronger statement and stays consistent with
the appendix.

**Currently:**

> The L4 semantic guardrail was the primary layer responsible for intercepting semantic camouflage variants that cleared L1 through L3.

**Should be:**

> L4 is the only layer positioned to intercept semantic camouflage variants that clear L1 through L3, since it is the only one that examines the model's response. On the representative run it caught 10 of the 71 that reached it, which is what leaves this category as the framework's principal residual vulnerability.

### C10. Chapter 4, Section 4.5.5 — an approximation that can be exact

**Currently:**

> ---roughly 5\% of the set, since short, user-typed questions rarely accumulate any of the six anomaly-score dimensions.

**Should be:**

> ---18 of 333 on the representative run, since short, user-typed questions rarely accumulate any of the six anomaly-score dimensions.

### C11. The two abstracts do not cover the same ground

The English abstract reports the external BIPIA validation, the second model, and the
61.3 per cent latency reduction. The Arabic abstract omits all three. A committee
reading both will notice that the Arabic version describes the earlier scope of the
work.

**Add to the Arabic abstract, after the sentence ending** `البالغة 333 استعلاماً` **:**

> كما انخفض زمن الاستجابة المتوسط بنسبة 61.3\% مقارنةً بالنظام غير المحمي، وهي نتيجة تفسّرها بنية الاعتراض المبكر: الهجمات التي تُحجب قبل وصولها إلى النموذج اللغوي لا تتكبد كلفته الحسابية أصلاً. وقد جرى التحقق من الإطار إضافةً إلى ذلك على معيار خارجي مستقل هو BIPIA، وعلى نموذج لغوي ثانٍ مختلف معمارياً هو Llama-3.2-3B، وأكد ذلك أن طبقات الدفاع العاملة على المدخلات تعمل بمعزل عن النموذج اللغوي الأساسي.

**Then delete the now-duplicated sentence:**

> فضلاً عن ذلك، يقلص إطار الدفاع زمن الاستجابة المتوسط مقارنةً بالنظام غير المحمي، نظراً لأن الهجمات تُعترض قبل وصولها إلى النموذج اللغوي.

### C12. Chapter 4 and Appendix B quote different margins for the same threshold

Both are correct and both are worth keeping, but a reader moving between them will
want to know why the numbers differ. Chapter 4 cites 0.006, the gap between the
threshold and the lowest of the five at-risk internal scores. Appendix B cites 0.0149,
the gap for the specific query it demonstrates. One clause resolves it.

**In Chapter 4 Section 4.5.5, currently:**

> the five internal benign responses closest to the boundary score between 0.186 and 0.2331, so 0.006 separates the nearest of them from a block.

**Should be:**

> the five internal benign responses closest to the boundary score between 0.186 and 0.2331, so 0.006 separates the nearest of them from a block. The two such queries demonstrated in Appendix~\ref{app:demo} score 0.1949 and 0.2189, both measured on the complete system.

---

## Part D. Verified correct, needing no attention

Checked in this pass against the source code, the recorded runs, or by recomputation.

**Applied correctly from the previous list.** The retrieval-threshold passage and the
L0 risk-band passage in Chapter 3; the L4 gate in Sections 3.3.1 and 3.3.5; Pattern 9
added to Section 3.3.3 and the count corrected in the Chapter 3 summary; the anomaly
threshold and its bar of 30.0 and 21.0 in Section 3.3.4; the semantic threshold
pointer in Section 3.3.5; Gap 2 in Chapter 2; the table footnote group in Chapter 2;
the tier-weight column in Table `tab:attack_distribution`; the L3 and L4 share and the
seed-to-seed variation in Section 4.5.3; the note under Table `tab:layer_results`; the
figure caption naming context poisoning; the false-positive description in
Section 4.5.5; the ten attack attempts in Section 4.5.10; the ablation sentence in the
Chapter 4 summary; the six limitations in Chapter 5; the obfuscation-variant paragraph
and the bypass mechanisms in Section 4.5.8; the maths in the fourth contribution of
Chapter 1; and the thresholds section itself, placed as 3.6 with the summary moving to
3.7.

**Figures confirmed.** Every category count and standard deviation in
Table `tab:attack_distribution` and `tab:dataset_breakdown`. The obfuscation shares of
12.73, 9.27, 8.87, 4.88 and 64.26 per cent over 5{,}005 attacks, and the designed
weights of 12, 10, 8, 5 and 65 per cent. The layer table of 158, 720, 24 and 10
summing to 912, and its percentages. 98.9 per cent blocked before inference. The
latency reduction of 61.3 per cent from 17.837 to 6.896 seconds. The blocked mean of
903.2 with a standard deviation of 10.8. The full ablation table. L4's contribution on
seed 42. The Wilson intervals of 0.05 to 1.68 per cent and 8.1 to 11.8 per cent, both
recomputed. McNemar's chi-squared of 901.0. Every row of the per-category table. The
semantic camouflage variant table summing to 602. All three example queries in
`tab:sc_examples`, re-run and confirmed to clear L0 through L3. The external outcome
table summing to 986, the factor of 3.6, and 70.3 per cent resisted. The external
false positive rate of 1.80 per cent, all six at L3, reproduced independently by the
L3 sweep. Nine of 29 categories carrying 77.1 per cent of compliances. Both
cross-model tables. Llama's precision of 70 per cent on its extra L4 firings. The
homoglyph figures of 73.9 to 88.1 per cent and 89.37 to 90.63 per cent. Every line
count and gating condition in Appendix A. All fifteen layer attributions and all
fifteen latencies in Appendix B.

**Cross-references.** All eleven labels introduced by the new material resolve, and
the eight defined in the thresholds section do not collide with anything the thesis
already defines. Appendix A and Appendix B keep the labels `app:code` and `app:demo`,
so the old appendices must be deleted rather than kept alongside the new ones.

**What the revision now carries that the submitted version did not.** A combinatorial
generator producing 1{,}455 distinct base strings drawn without replacement, replacing
80 strings drawn with replacement. A benign set of 333 unique queries including
deliberately sensitive phrasings, replacing 12 strings that could not produce a false
positive. Five seeds on each of two models under frozen defense code. An independent
external benchmark, a never-tuned holdout, and 300 real human-written queries. A
compliance measure separating reaching the model from obeying it, at complete coverage
and on untruncated responses. A direct per-query layer attribution that agrees exactly
with the ablation-derived figures. A two-sided sweep for each of the two blocking
thresholds. A per-query demonstration measured on the evaluation hardware. And a
diagnosed, quantified cause for every false positive that remains.
