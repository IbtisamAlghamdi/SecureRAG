# -*- coding: utf-8 -*-
"""Builds SecureRAG_Revision_Summary.pdf -- the one-table supervisor-facing
summary of what changed after the reviewers' report: Change / Before /
After / Reason, A4 landscape.

Every figure in the table below is transcribed from FINAL_RESULTS.md and
REVISION_LOG_PART1-4.md, which in turn come from real runs of the frozen
defense code. Nothing here is estimated or recomputed -- if a number in
those documents changes, change it here too rather than regenerating it
from a different source.

Requires: pip install reportlab
Usage:    python3 make_revision_summary_pdf.py
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

INK    = colors.HexColor("#1c1c1c")
MUTED  = colors.HexColor("#5c5c5c")
RULE   = colors.HexColor("#c9c9c9")
HAIR   = colors.HexColor("#e4e4e4")
BAND   = colors.HexColor("#f2f2ef")
ACCENT = colors.HexColor("#2f4858")

def P(txt, size=7.6, leading=9.6, color=INK, font="Helvetica", space=0):
    return Paragraph(txt, ParagraphStyle(
        "c", fontName=font, fontSize=size, leading=leading,
        textColor=color, spaceAfter=space))

def head(txt):
    return Paragraph(txt, ParagraphStyle(
        "h", fontName="Helvetica-Bold", fontSize=7.6, leading=9.6,
        textColor=colors.white))

def name(txt):
    return P(f"<b>{txt}</b>")

def group(txt):
    return Paragraph(txt.upper(), ParagraphStyle(
        "g", fontName="Helvetica-Bold", fontSize=6.9, leading=9,
        textColor=ACCENT))

# ── the table ────────────────────────────────────────────────────────────
G = "__GROUP__"
rows = [
    [head("Change"), head("Before"), head("After"), head("Reason")],

    [G, group("Evaluation set — the answer to the co-design-bias criticism"), "", ""],

    [name("Attack generator"),
     P("8 tiers &times; 10 hand-written strings = <b>80</b> unique attacks, sampled "
       "<b>with</b> replacement. One string appeared <b>25 times</b> in a single "
       "1,001-attack batch."),
     P("Combinatorial <i>template &times; variable-pool</i> architecture: <b>1,455</b> unique "
       "base strings, sampled <b>without</b> replacement. <b>Zero</b> duplicates across all "
       "five seeds. Over-requesting a tier now raises an error instead of repeating."),
     P("A 1,001-attack run drawn from 80 strings is a test of 80 attacks replicated twelve "
       "times: the effective sample size was 80, so every confidence interval computed on "
       "n=1,001 was invalid, and detection could not be distinguished from memorising the "
       "author's own strings.")],

    [name("Benign query generator"),
     P("<b>12</b> hand-written questions, sampled with replacement (~28 copies of each per "
       "333-query batch). None contained a word the detector treats as risky."),
     P("Combinatorial pools, <b>333 unique</b> queries per batch, deliberately including "
       "benign-but-sensitive phrasings (e.g. &ldquo;how do I <i>override</i> a method&rdquo;, "
       "&ldquo;.gitignore configuration&rdquo;). Asserted by an automated check."),
     P("The old set was <b>structurally incapable of producing a false positive</b>, so the "
       "reported FPR of 0.00&nbsp;% was not a measurement of anything. This is the single "
       "most important correction in the revision.")],

    [name("L2 rule patterns"),
     P("Patterns fitted, unintentionally, to the 80 written strings. On a diverse batch "
       "pre-L4 detection fell to <b>60.1&nbsp;%</b>."),
     P("Patterns re-derived from each attack tier&rsquo;s own enumerable structure &mdash; never "
       "from held-out data. Pre-L4 detection <b>88.0&nbsp;%</b>."),
     P("The 8.4-point drop from 68.5&nbsp;% to 60.1&nbsp;% when the generator was replaced is the "
       "<b>measured size of the co-design bias</b>, observed inside the project&rsquo;s own "
       "evaluation. Coverage was then rebuilt on structure rather than vocabulary.")],

    [G, group("Metrics and definitions"), "", ""],

    [name("Attack success rate<br/>definition"),
     P("ASR was computed as the complement of the detection rate. Every response that "
       "<b>reached the model</b> was counted as a successful attack."),
     P("Reaching the model and complying are now measured separately. External: "
       "<b>57.40&nbsp;%</b> reached the model, <b>15.92&nbsp;%</b> actually complied "
       "(Mistral-7B). <b>70.3&nbsp;%</b> of attacks that passed every defense layer were "
       "refused by the model itself."),
     P("The second reviewer criticism. Equating reach with success overstates the attack "
       "success rate by a factor of <b>3.6&times;</b>. Compliance is judged by comparing the "
       "response against the literal injected instruction and against the real question, "
       "with ambiguous cases counted as <i>not</i> complied &mdash; so the figure is a lower bound.")],

    [name("Injected-instruction<br/>recovery"),
     P("A line-split heuristic that only worked for <i>start</i> and <i>end</i> positions "
       "&mdash; roughly <b>70&nbsp;%</b> coverage, with mid-document injections silently dropped."),
     P("Ground-truth lookup of each sample&rsquo;s attack identifier against BIPIA&rsquo;s own "
       "source files. <b>100&nbsp;%</b> coverage of reached-model rows for both models."),
     P("The excluded rows were being counted as non-compliant by default, and the per-verdict "
       "percentages divided by the smaller extractable count. The literal source text replaces "
       "the heuristic entirely.")],

    [name("Response text used<br/>for scoring"),
     P("A 500-character snippet. <b>52.4&nbsp;%</b> of responses were truncated."),
     P("The full untruncated response."),
     P("Truncation depressed the benign-similarity term (0.297 vs 0.556) and therefore "
       "<b>over-reported compliance</b>. Re-measuring on full text was a prerequisite for "
       "trusting the number.")],

    [name("Layer contribution<br/>table"),
     P("Derived indirectly from cumulative ablation deltas: L1&nbsp;195 / L2&nbsp;640 / "
       "L3&nbsp;34 / L4&nbsp;41."),
     P("Direct per-query tally of which layer actually fired: <b>L1&nbsp;158 / L2&nbsp;720 / "
       "L3&nbsp;24 / L4&nbsp;10</b> (912 blocked + 89 reached = 1,001). Both methods now agree "
       "on all four layers."),
     P("A derived figure was being reported as a measurement. The direct tally is the primary "
       "number; the ablation deltas are retained as an independent cross-check, and their exact "
       "agreement validates both.")],

    [G, group("Models, runs and reproducibility"), "", ""],

    [name("Models evaluated"),
     P("One &mdash; Mistral-7B-Instruct v0.2."),
     P("Two &mdash; Mistral-7B-Instruct v0.2 (primary) and Llama-3.2-3B-Instruct (secondary), "
       "under identical frozen code, corpus and thresholds."),
     P("Tests whether the defense generalises across architectures, and validates the design: "
       "L0&ndash;L3 inspect input only, and returned <b>numerically identical</b> ASR on both models "
       "at every ablation step. <b>Every cross-model difference sits in L4 alone</b>, exactly "
       "as the architecture predicts.")],

    [name("Runs and statistics"),
     P("A single run. No variance estimate, no significance test."),
     P("<b>5 seeds &times; 2 models.</b> Internal ASR <b>9.77&nbsp;% &plusmn; 1.08&nbsp;%</b> (Mistral) "
       "and 10.33&nbsp;% &plusmn; 0.88&nbsp;% (Llama); Wilson 95&nbsp;% intervals and McNemar&rsquo;s "
       "test reported throughout (&chi;&sup2;&nbsp;=&nbsp;901.0, <i>p</i>&nbsp;&lt;&nbsp;0.001)."),
     P("A single run cannot support a claim of stability. The two models&rsquo; intervals overlap, "
       "so the difference between them is <b>not</b> statistically meaningful &mdash; which is itself "
       "the finding worth reporting.")],

    [name("External validation"),
     P("None. All attacks and all benign queries were written by the author."),
     P("<b>BIPIA</b> (Microsoft, KDD&nbsp;&rsquo;25): 986 attacks and 333 benign documents, plus a "
       "fresh never-tuned holdout and <b>300 real human-written queries</b> drawn from Natural "
       "Questions, SciFact and FiQA."),
     P("An independent benchmark the author had no role in designing is the only structural answer "
       "to co-design bias. End-to-end, <b>84.08&nbsp;%</b> of BIPIA attacks were neutralised on "
       "Mistral-7B.")],

    [name("Defense code state"),
     P("Modified during the evaluation period."),
     P("Frozen since a single commit; no defense module has changed since. All reported figures "
       "come from one identical code state."),
     P("Without a freeze, results from different dates are not comparable to each other and cannot "
       "be reproduced from the repository as submitted.")],

    [G, group("Findings recorded but deliberately not acted on"), "", ""],

    [name("External false<br/>positives"),
     P("<b>1.80&nbsp;%</b> (6 of 333), cause unknown."),
     P("Fully root-caused: all six are dense markdown tables. The special-character-ratio rule "
       "counts table punctuation as obfuscation evidence, raising L0 risk to HIGH, which in turn "
       "lowers L3&rsquo;s own threshold. A validated fix takes it to <b>0.30&nbsp;%</b> at a cost of "
       "one missed attack in 1,001 &mdash; and was <b>not applied</b>."),
     P("Applying it would invalidate every reported result and require re-running the entire "
       "evaluation. It is documented as a diagnosed, quantified limitation with a known remedy "
       "rather than folded in silently after the fact.")],

    [name("Reliability of the<br/>Llama compliance figure"),
     P("&mdash;"),
     P("Reported (23.73&nbsp;%) <b>with</b> its instrument limits stated: 28.7&nbsp;% of its cases "
       "are ambiguous and the figure moves 17.75 points across the margin sweep, against "
       "1.9&nbsp;% and 2.44 points for Mistral."),
     P("The classifier discriminates poorly on this model&rsquo;s responses. Stating that is a "
       "limitation of the <i>measurement</i>, not a security claim about the model, and it prevents "
       "the weaker number from being read as equivalent to the stronger one.")],
]

# ── document ─────────────────────────────────────────────────────────────
PAGE = landscape(A4)
LM = RM = 13 * mm
TM = 16 * mm
BM = 13 * mm
avail = PAGE[0] - LM - RM
col_w = [avail * f for f in (0.135, 0.235, 0.29, 0.34)]

t = Table(rows, colWidths=col_w, repeatRows=1)

style = [
    ("BACKGROUND",   (0, 0), (-1, 0), ACCENT),
    ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING",   (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ("LEFTPADDING",  (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING",   (0, 0), (-1, 0), 4.5),
    ("BOTTOMPADDING",(0, 0), (-1, 0), 4.5),
    ("LINEBELOW",    (0, 1), (-1, -1), 0.35, HAIR),
    ("LINEBELOW",    (0, -1), (-1, -1), 0.7, RULE),
]
for i, r in enumerate(rows):
    if r[0] == G:
        style += [("SPAN", (0, i), (-1, i)),
                  ("BACKGROUND", (0, i), (-1, i), BAND),
                  ("TOPPADDING", (0, i), (-1, i), 6),
                  ("BOTTOMPADDING", (0, i), (-1, i), 3.5),
                  ("LINEBELOW", (0, i), (-1, i), 0.35, RULE)]
        rows[i] = [r[1], "", "", ""]
t = Table(rows, colWidths=col_w, repeatRows=1)
t.setStyle(TableStyle(style))

story = [t, Spacer(1, 6 * mm),
         P("Every figure above is reproduced from a run of the frozen evaluation code; none is "
           "estimated. Several numbers are worse than those originally submitted &mdash; the internal "
           "false-positive rate moved from 0.00&nbsp;% to 0.12&nbsp;%&nbsp;&plusmn;&nbsp;0.16&nbsp;%, and "
           "<i>semantic&nbsp;camouflage</i> attack success from 39.9&nbsp;% to 59.1&nbsp;% &mdash; because the "
           "earlier evaluation was structurally unable to expose the errors it contained. "
           "Full change history, root cause and verification for each item: revision log, parts 1&ndash;4.",
           size=7.2, leading=10, color=MUTED)]

def decorate(canv, doc):
    canv.saveState()
    canv.setFont("Helvetica-Bold", 10.5)
    canv.setFillColor(INK)
    canv.drawString(LM, PAGE[1] - TM + 6.5*mm, "SecureRAG — Summary of Revisions")
    canv.setFont("Helvetica", 7.4)
    canv.setFillColor(MUTED)
    canv.drawString(LM, PAGE[1] - TM + 2.8*mm,
                    "Changes made to the evaluation methodology, the models tested, and the "
                    "reported figures, following the reviewers’ report")
    canv.drawRightString(PAGE[0] - RM, PAGE[1] - TM + 6.5*mm, "August 2026")
    canv.setStrokeColor(RULE); canv.setLineWidth(0.7)
    canv.line(LM, PAGE[1] - TM + 1.0*mm, PAGE[0] - RM, PAGE[1] - TM + 1.0*mm)
    canv.setFont("Helvetica", 6.8)
    canv.setFillColor(MUTED)
    canv.drawRightString(PAGE[0] - RM, BM - 6*mm, f"{doc.page}")
    canv.restoreState()

doc = BaseDocTemplate("SecureRAG_Revision_Summary.pdf", pagesize=PAGE,
                      leftMargin=LM, rightMargin=RM, topMargin=TM, bottomMargin=BM,
                      title="SecureRAG - Summary of Revisions",
                      subject="Revision summary")
frame = Frame(LM, BM, avail, PAGE[1] - TM - BM, id="f",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=decorate)])
doc.build(story)
print("built")
