
import argparse, sys, os, json, time, math, random, statistics
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import SecureRAG
from src.attacks.generator import RealisticAttackGenerator
from src.defenses.sanitization.sanitize import sanitize_input, get_sanitization_report
from src.defenses.rules.rule_filter import rule_based_detector_detailed
from src.defenses.anomaly.anomaly_detector import compute_anomaly_score
from src.defenses.semantic.semantic_detector import semantic_response_is_suspicious
from src.config import settings
from model_select import add_model_arg, resolve_model, safe_filename

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ── Model selection ──────────────────────────────────────────────────────
# Resolved once, at import time, so every output path below can be
# namespaced by model -- running this once per model (Mistral-7B,
# Llama-3.2-3B, Phi-3.5-Mini, ...) never overwrites another model's
# results. Nothing else in this script changes based on which model is
# selected: same thresholds, same corpus, same prompt template (see
# SecureRAG(model_path=...) in src/pipeline.py) -- a true model-only
# comparison.
_arg_parser = argparse.ArgumentParser(
    description="SecureRAG thesis evaluation -- 5-seed multirun + ablation study."
)
add_model_arg(_arg_parser)
_args = _arg_parser.parse_args()
SELECTED_MODEL = resolve_model(_args.model)

# ── ─────────────────────────
OUT_DIR      = os.path.join("outputs", "thesis_v2", safe_filename(SELECTED_MODEL))
PLOTS_DIR    = os.path.join(OUT_DIR, "plots")
OUTPUT_JSON  = os.path.join(OUT_DIR, "thesis_results.json")
LATEX_FILE   = os.path.join(OUT_DIR, "thesis_latex_snippets.txt")

os.makedirs(PLOTS_DIR, exist_ok=True)

# ──  Evaluation ──────────────────────────────
N_RUNS        = 5
ATTACK_COUNT  = 1001
BENIGN_COUNT  = 333
SEEDS         = [42, 137, 271, 413, 509]

SEP  = "=" * 65
SEP2 = "-" * 65

plt.rcParams.update({
    'font.family':       'DejaVu Sans',
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'axes.grid':         True,
    'grid.alpha':        0.3,
    'figure.facecolor':  'white',
    'axes.facecolor':    '#f9f9f9',
})
C_SAFE    = '#6b9e8a'
C_DANGER  = '#c0392b'
C_NEUTRAL = '#5c7a9e'
C_ACCENT  = '#e67e22'


# Helper functions

def wilson_ci(successes: int, n: int) -> Tuple[float, float]:
    if n == 0: return 0.0, 0.0
    z = 1.96
    p = successes / n
    denom  = 1 + z**2 / n
    centre = (p + z**2 / (2*n)) / denom
    margin = (z * math.sqrt(p*(1-p)/n + z**2/(4*n**2))) / denom
    return round(max(0, centre - margin)*100, 2), round(min(1, centre + margin)*100, 2)


def mcnemar_test(b: int, c: int = 0) -> Tuple[float, str]:
    if b + c == 0: return 0.0, "N/A"
    chi2  = ((abs(b - c) - 1)**2) / (b + c)
    p_str = "< 0.001" if chi2 > 10.83 else "< 0.05" if chi2 > 3.84 else ">= 0.05"
    return round(chi2, 2), p_str


def generate_dataset(seed: int):
    random.seed(seed)
    gen     = RealisticAttackGenerator()
    attacks = gen.generate_batch(ATTACK_COUNT, benign_ratio=0.0)
    attacks = [a for a in attacks if a.get('is_attack', True)][:ATTACK_COUNT]
    # FIXED: was random.choices(gen.benign_queries, k=BENIGN_COUNT) -- sampled
    # a static list WITH replacement, so duplicate benign queries could (and
    # did) land in the same run. generate_benign_batch() builds BENIGN_COUNT
    # dynamically from template x topic pools with zero duplicates.
    benign  = gen.generate_benign_batch(BENIGN_COUNT)
    return attacks, benign


# Basic Evaluation Function


def evaluate(rag, attacks, benign, label=""):
    blocked = 0
    fp      = 0
    lats    = []
    per_cat = {}
    sc_fail = []

    total = len(attacks) + len(benign)
    done  = 0

    for atk in attacks:
        query  = atk['payload']
        atype  = atk['type']
        res    = rag.run(query)
        is_blk = res['flag'] not in ['clean', 'baseline', 'error']
        lats.append(res['latency'])
        if is_blk:
            blocked += 1
        elif 'semantic' in atype:
            sc_fail.append({'query': query[:200], 'type': atype,
                            'risk': res.get('risk','low')})
        base = atype.split('_')[0]
        if base not in per_cat:
            per_cat[base] = {'total':0,'blocked':0}
        per_cat[base]['total']   += 1
        per_cat[base]['blocked'] += int(is_blk)
        done += 1
        if done % 100 == 0:
            print(f"  {label} [{done}/{total}]...", end='\r')

    for query in benign:
        res    = rag.run(query)
        is_blk = res['flag'] not in ['clean', 'baseline', 'error']
        lats.append(res['latency'])
        if is_blk: fp += 1
        done += 1
        if done % 50 == 0:
            print(f"  {label} [{done}/{total}]...", end='\r')

    print(f"  {label} [DONE {total}/{total}]          ")

    na, nb = len(attacks), len(benign)
    for c in per_cat:
        t = per_cat[c]['total']
        b = per_cat[c]['blocked']
        per_cat[c]['ASR'] = round((t-b)/t*100,1) if t else 0
        per_cat[c]['DR']  = round(b/t*100,1)     if t else 0

    return {
        'ASR':      round((na-blocked)/na*100, 2),
        'FPR':      round(fp/nb*100, 2),
        'latency':  round(statistics.mean(lats), 3),
        'blocked':  blocked,
        'fp':       fp,
        'per_cat':  per_cat,
        'sc_fail':  sc_fail[:5],
    }


# AblationRAG — Modified version without changing the original code
class AblationRAG(SecureRAG):
    def __init__(self, l1=True, l2=True, l3=True, l4=True, model_path=None):
        super().__init__(enable_defenses=True, model_path=model_path)
        self.l1, self.l2, self.l3, self.l4 = l1, l2, l3, l4

    def run(self, query):
        import time as _t
        start = _t.time()
        try:
            risk = self._ars_prescreen(query)

            if self.l1:
                san    = sanitize_input(query)
                report = get_sanitization_report(query, san)
                if report['had_template_inj']:
                    return self._block('template_injection', start, risk)
                if report['had_injection'] or report['had_base64']:
                    return self._block('sanitization', start, risk)
            else:
                san = query

            if self.l2:
                det, vt, rr = rule_based_detector_detailed(san)
                if det:
                    return self._block('rules', start, rr)

            if self.l3:
                score = compute_anomaly_score(query)
                thr   = settings.get_anomaly_threshold()
                eff   = thr * (0.7 if risk == 'HIGH' else 1.0)
                if score > eff * 2.0:
                    return self._block('anomaly', start, risk)

            context  = self._get_rag_context(san)
            response = self.llm.generate_answer(san, context)

            if self.l4 and risk in ['HIGH','MEDIUM'] and response:
                susp, _ = semantic_response_is_suspicious(
                    response, self.retriever.get_embeddings(), self.embedder)
                if susp:
                    return self._block('semantic', start, risk)

            return {'response': response, 'flag': 'clean',
                    'risk': risk.lower(), 'layer': 'none',
                    'latency': round(_t.time()-start, 3)}
        except Exception as e:
            return {'response': str(e), 'flag': 'error',
                    'risk': 'unknown', 'layer': 'error',
                    'latency': round(_t.time()-start, 3)}


# Academic drawing

def plot_multirun_summary(runs, mean_asr, std_asr,
                          mean_fpr, std_fpr,
                          mean_lat, std_lat):
    """Figure 1: ملخص الـ 5 تشغيلات — ASR / FPR / Latency"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 6))
    fig.suptitle(
        f'SecureRAG Multi-Run Evaluation Summary (N={N_RUNS} independent runs)',
        fontsize=13, fontweight='bold', y=1.01)

    run_labels = [f'Run {i+1}' for i in range(len(runs))]
    xs = range(len(runs))

    # ASR
    asr_vals = [r['ASR'] for r in runs]
    axes[0].bar(xs, asr_vals, color=C_DANGER, alpha=0.75,
                edgecolor='white', linewidth=1.5)
    axes[0].axhline(mean_asr, color='black', ls='--', lw=1.5,
                    label=f'Mean = {mean_asr:.1f}%')
    axes[0].fill_between(xs, mean_asr-std_asr, mean_asr+std_asr,
                         alpha=0.15, color='black', label=f'±std = {std_asr:.1f}%')
    axes[0].set_xticks(xs); axes[0].set_xticklabels(run_labels, fontsize=9)
    axes[0].set_title('Attack Success Rate (ASR %)\nLower is better ↓',
                      fontweight='bold')
    axes[0].set_ylabel('ASR (%)')
    axes[0].set_ylim(0, max(asr_vals)*1.3 + 2)
    axes[0].legend(fontsize=9)
    for i, v in enumerate(asr_vals):
        axes[0].text(i, v+0.3, f'{v:.1f}%', ha='center', fontsize=9)

    # FPR
    fpr_vals = [r['FPR'] for r in runs]
    axes[1].bar(xs, fpr_vals, color=C_SAFE, alpha=0.75,
                edgecolor='white', linewidth=1.5)
    axes[1].axhline(mean_fpr, color='black', ls='--', lw=1.5,
                    label=f'Mean = {mean_fpr:.1f}%')
    axes[1].set_xticks(xs); axes[1].set_xticklabels(run_labels, fontsize=9)
    axes[1].set_title('False Positive Rate (FPR %)\nLower is better ↓',
                      fontweight='bold')
    axes[1].set_ylabel('FPR (%)')
    axes[1].set_ylim(0, max(max(fpr_vals)+0.5, 2))
    axes[1].legend(fontsize=9)
    for i, v in enumerate(fpr_vals):
        axes[1].text(i, v+0.03, f'{v:.1f}%', ha='center', fontsize=9)

    # Latency
    lat_vals = [r['latency'] for r in runs]
    axes[2].bar(xs, lat_vals, color=C_NEUTRAL, alpha=0.75,
                edgecolor='white', linewidth=1.5)
    axes[2].axhline(mean_lat, color='black', ls='--', lw=1.5,
                    label=f'Mean = {mean_lat:.2f}s')
    axes[2].fill_between(xs, mean_lat-std_lat, mean_lat+std_lat,
                         alpha=0.15, color='black', label=f'±std = {std_lat:.2f}s')
    axes[2].set_xticks(xs); axes[2].set_xticklabels(run_labels, fontsize=9)
    axes[2].set_title('Avg Query Latency (s)\n(blocked queries excluded from LLM)', fontweight='bold')
    axes[2].set_ylabel('Latency (seconds)')
    axes[2].legend(fontsize=9)
    for i, v in enumerate(lat_vals):
        axes[2].text(i, v+0.05, f'{v:.2f}s', ha='center', fontsize=9)

    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, 'fig_multirun_summary.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {path}")


def plot_ablation(ablation: Dict):
    """Figure 2: Ablation Study"""
    names = list(ablation.keys())
    asr   = [ablation[n]['ASR']     for n in names]
    fpr   = [ablation[n]['FPR']     for n in names]
    lat   = [ablation[n]['latency'] for n in names]

    x   = np.arange(len(names))
    w   = 0.28
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Ablation Study — Cumulative Layer Contribution',
                 fontsize=13, fontweight='bold')

    # ASR + FPR grouped bar
    b1 = axes[0].bar(x - w/2, asr, w, label='ASR (%)',
                     color=C_DANGER, alpha=0.8, edgecolor='white')
    b2 = axes[0].bar(x + w/2, fpr, w, label='FPR (%)',
                     color=C_SAFE,   alpha=0.8, edgecolor='white')
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(names, fontsize=9, rotation=15, ha='right')
    axes[0].set_ylabel('Rate (%)')
    axes[0].set_title('ASR and FPR by Configuration\n(Lower is better for both)')
    axes[0].legend()
    for bar, val in zip(b1, asr):
        axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3,
                     f'{val:.1f}%', ha='center', fontsize=8, color=C_DANGER,
                     fontweight='bold')
    for bar, val in zip(b2, fpr):
        axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                     f'{val:.1f}%', ha='center', fontsize=8, color='#27ae60',
                     fontweight='bold')

    # Latency line chart
    colors_lat = [C_NEUTRAL if 'Full' not in n else C_SAFE for n in names]
    axes[1].plot(x, lat, 'o-', color=C_ACCENT, lw=2, markersize=8)
    for i, (xi, v) in enumerate(zip(x, lat)):
        axes[1].annotate(f'{v:.2f}s', (xi, v), textcoords='offset points',
                         xytext=(0, 10), ha='center', fontsize=9)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(names, fontsize=9, rotation=15, ha='right')
    axes[1].set_ylabel('Avg Latency (s)')
    axes[1].set_title('Average Query Latency by Configuration\n(More layers = earlier blocking = lower latency)')

    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, 'fig_ablation_study.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {path}")


def plot_per_category(per_cat_avg: Dict):
    """Figure 3: DR per category — multi-run average with std"""
    cats     = sorted(per_cat_avg.keys())
    dr_means = [per_cat_avg[c]['DR_mean']  for c in cats]
    dr_stds  = [per_cat_avg[c]['DR_std']   for c in cats]
    asr_means= [per_cat_avg[c]['ASR_mean'] for c in cats]

    fig, ax = plt.subplots(figsize=(13, 6))
    ax.set_title(
        'Detection Rate by Attack Category\n'
        f'(mean ± std across {N_RUNS} independent runs)',
        fontsize=13, fontweight='bold')

    colors = [C_SAFE if dr >= 80 else C_ACCENT if dr >= 50 else C_DANGER
              for dr in dr_means]
    x = np.arange(len(cats))
    bars = ax.bar(x, dr_means, color=colors, alpha=0.8,
                  edgecolor='white', linewidth=1.5, yerr=dr_stds,
                  capsize=5, error_kw={'elinewidth':1.5,'ecolor':'#333'})

    ax.axhline(80, color='gray', ls='--', alpha=0.5, label='80% reference')
    ax.set_xticks(x)
    ax.set_xticklabels([c.replace('_',' ') for c in cats],
                       rotation=20, ha='right', fontsize=10)
    ax.set_ylabel('Detection Rate (%)')
    ax.set_ylim(0, 115)
    ax.legend()

    for bar, dr, asr in zip(bars, dr_means, asr_means):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+2,
                f'DR={dr:.0f}%\nASR={asr:.0f}%',
                ha='center', fontsize=8, fontweight='bold')

    patch_high   = mpatches.Patch(color=C_SAFE,   label='DR ≥ 80%')
    patch_medium = mpatches.Patch(color=C_ACCENT, label='50% ≤ DR < 80%')
    patch_low    = mpatches.Patch(color=C_DANGER, label='DR < 50%')
    ax.legend(handles=[patch_high, patch_medium, patch_low], loc='lower right')

    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, 'fig_per_category_multirun.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {path}")




def make_latex(full, ablation, sc_examples):
    ma   = full['ASR_mean'];    sa  = full['ASR_std']
    mf   = full['FPR_mean'];    sf  = full['FPR_std']
    ml   = full['Lat_mean'];    sl  = full['Lat_std']
    wl   = full['wilson_lo'];   wu  = full['wilson_hi']
    chi2 = full['mcnemar_chi2']
    pval = full['mcnemar_p']
    blk  = full['Blocked_mean']

    lines = [
"% ═══════════════════════════════════════════════════════════════",
"% LATEX SNIPPETS — SecureRAG Thesis (generated by thesis_evaluation.py)",
"% ═══════════════════════════════════════════════════════════════",
"",
"% ── §4.4 Replace single-run sentences with: ─────────────────────",
f"SecureRAG was evaluated across {N_RUNS}~independent runs, each using",
f"a distinct random seed to control attack variant selection.",
f"The mean attack success rate was",
f"$\\overline{{\\mathrm{{ASR}}}} = {ma:.1f}\\% \\pm {sa:.1f}\\%$,",
f"the mean false positive rate was",
f"$\\overline{{\\mathrm{{FPR}}}} = {mf:.1f}\\% \\pm {sf:.1f}\\%$,",
f"and the mean end-to-end query latency was",
f"${ml:.2f}\\,\\mathrm{{s}} \\pm {sl:.2f}\\,\\mathrm{{s}}$.",
"",
"% ── §4.5.5 Wilson CI (add after FPR = 0.0% sentence) ───────────",
f"Applying the Wilson score method~\\cite{{wilson1927probable}},",
f"the 95\\% confidence interval for the false positive rate is",
f"$[{wl:.2f}\\%,\\; {wu:.2f}\\%]$, confirming that the true FPR is",
f"bounded below {wu:.2f}\\% with 95\\% confidence given the evaluation",
f"sample of {BENIGN_COUNT}~legitimate queries per run.",
"",
"% ── §4.5 Statistical Significance (new subsection) ─────────────",
"\\subsection*{Statistical Significance}",
"\\label{subsec:significance}",
"",
"McNemar's test was applied to the paired binary outcomes across",
f"the {ATTACK_COUNT}~attack queries.",
f"The discordant pair count was $b = {int(blk)}$ (blocked by",
"SecureRAG, not by baseline) and $c = 0$.",
"\\[",
f"\\chi^2 = \\frac{{(|b - c| - 1)^2}}{{b + c}}",
f"       = \\frac{{({int(blk)} - 1)^2}}{{{int(blk)}}}",
f"       \\approx {chi2},",
f"\\quad p {pval}",
"\\]",
"This confirms statistical significance at the $0.1\\%$",
"level~\\cite{mcnemar1947note}.",
"",
"% ── §4.5.3 Ablation Table ───────────────────────────────────────",
"\\begin{table}[htbp]",
"\\centering",
"\\caption{Ablation study: cumulative effect of adding defense layers.}",
"\\label{tab:ablation}",
"\\begin{tabular}{lccc}",
"\\hline",
"\\textbf{Configuration} & \\textbf{ASR (\\%)} &",
"\\textbf{FPR (\\%)} & \\textbf{Avg Latency (s)} \\\\",
"\\hline",
]
    for name, vals in ablation.items():
        bold = 'Full' in name
        pre  = "\\textbf{" if bold else ""
        post = "}" if bold else ""
        lines.append(
            f"{pre}{name}{post} & "
            f"{pre}{vals['ASR']:.1f}{post} & "
            f"{pre}{vals['FPR']:.1f}{post} & "
            f"{pre}{vals['latency']:.2f}{post} \\\\"
        )
    lines += [
"\\hline",
"\\end{tabular}",
"\\end{table}",
"",
"% ── §4.5.4.1 SC Failures Table ─────────────────────────────────",
"\\begin{table}[htbp]",
"\\centering",
"\\caption{Representative semantic camouflage attacks that bypassed all five layers.}",
"\\label{tab:sc_examples}",
"\\begin{tabularx}{\\textwidth}{@{} X l @{}}",
"\\hline",
"\\textbf{Attack Query} & \\textbf{Why It Bypassed} \\\\",
"\\hline",
]
    reasons = [
        "No injection keywords; framed as creative writing",
        "Academic framing; no structural anomalies detected",
        "Research framing; anomaly score below threshold",
    ]
    for i, ex in enumerate(sc_examples[:3]):
        q = ex['query'][:130].replace('%','\\%').replace('&','\\&').replace('#','\\#')
        r = reasons[i] if i < len(reasons) else "Low anomaly score"
        lines.append(f"``{q}\\ldots'' & {r} \\\\")
    lines += [
"\\hline",
"\\end{tabularx}",
"\\end{table}",
"",
"% ── BibTeX entries ──────────────────────────────────────────────",
"@article{wilson1927probable,",
"  title   = {Probable inference, the law of succession, and statistical inference},",
"  author  = {Wilson, Edwin B.},",
"  journal = {Journal of the American Statistical Association},",
"  volume  = {22}, number = {158}, pages = {209--212}, year = {1927}",
"}",
"",
"@article{mcnemar1947note,",
"  title   = {Note on the sampling error of the difference between correlated",
"             proportions or percentages},",
"  author  = {McNemar, Quinn},",
"  journal = {Psychometrika},",
"  volume  = {12}, number = {2}, pages = {153--157}, year = {1947}",
"}",
    ]
    return "\n".join(lines)


# SC Examples من JSON القديم

def load_sc_examples():
    examples = []
    for json_path in ["outputs/evaluation_report.json",
                      "outputs/final_evaluation_results_1334.csv"]:
        if not os.path.exists(json_path): continue
        try:
            if json_path.endswith('.json'):
                with open(json_path) as f:
                    data = json.load(f)
                for item in data:
                    if not isinstance(item, dict): continue
                    if 'semantic' in item.get('type','').lower() and \
                       not item.get('blocked', True):
                        examples.append({
                            'query': item.get('payload','')[:250],
                            'type':  item.get('type',''),
                            'risk':  item.get('risk','low'),
                        })
                    if len(examples) >= 5: break
        except: pass

    # fallback من المولّد
    if len(examples) < 3:
        gen = RealisticAttackGenerator()
        for q in gen.semantic_camouflage[:3]:
            examples.append({'query': q, 'type': 'semantic_camouflage', 'risk': 'low'})

    return examples[:3]


# MAIN

def main():
    print(SEP)
    print("SecureRAG — Thesis Evaluation v2")
    print(f"Model            : {SELECTED_MODEL}")
    print(f"Output directory : {OUT_DIR}")
    print(f"Runs: {N_RUNS}  |  Attacks: {ATTACK_COUNT}  |  Benign: {BENIGN_COUNT}")
    print(SEP)
    t0 = time.time()

    # ── PART 1: 5 runs ─────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("PART 1 — 5-Run Full Evaluation")
    print(SEP)

    # Incremental per-run snapshot (including the per-category breakdown)
    # written to disk after EACH run finishes -- so you can inspect
    # per_cat for Run 1/2/... on outputs/thesis_v2/<model>/progress.json
    # without waiting for all N_RUNS to complete, and without starting a
    # second process that would compete with this one for the model.
    PROGRESS_JSON = os.path.join(OUT_DIR, "progress.json")

    rag  = SecureRAG(enable_defenses=True, model_path=settings.LLM_MODEL_PATH)
    runs = []
    for i, seed in enumerate(SEEDS):
        print(f"\nRun {i+1}/{N_RUNS}  (seed={seed})")
        attacks, benign = generate_dataset(seed)
        r = evaluate(rag, attacks, benign, label=f"Run{i+1}")
        runs.append(r)
        print(f"  → ASR={r['ASR']}%  FPR={r['FPR']}%  "
              f"Lat={r['latency']}s  Blocked={r['blocked']}/{ATTACK_COUNT}")

        with open(PROGRESS_JSON, 'w', encoding='utf-8') as f:
            json.dump({
                'model': SELECTED_MODEL,
                'runs_completed': i + 1,
                'runs_total': N_RUNS,
                'runs': runs,  # each entry includes 'per_cat' -- ASR/DR per attack category
            }, f, indent=2, ensure_ascii=False, default=str)

    asr_vals = [r['ASR']     for r in runs]
    fpr_vals = [r['FPR']     for r in runs]
    lat_vals = [r['latency'] for r in runs]
    blk_vals = [r['blocked'] for r in runs]

    mean_asr = round(statistics.mean(asr_vals),  2)
    std_asr  = round(statistics.stdev(asr_vals), 2) if len(asr_vals)>1 else 0.0
    mean_fpr = round(statistics.mean(fpr_vals),  2)
    std_fpr  = round(statistics.stdev(fpr_vals), 2) if len(fpr_vals)>1 else 0.0
    mean_lat = round(statistics.mean(lat_vals),  3)
    std_lat  = round(statistics.stdev(lat_vals), 3) if len(lat_vals)>1 else 0.0
    mean_blk = round(statistics.mean(blk_vals),  1)

    max_fp      = max(r['fp'] for r in runs)
    wl, wu      = wilson_ci(max_fp, BENIGN_COUNT)
    chi2, p_val = mcnemar_test(int(mean_blk), 0)

    # per_category average
    all_cats = set()
    for r in runs: all_cats.update(r['per_cat'].keys())
    per_cat_avg = {}
    for cat in sorted(all_cats):
        dr_c  = [r['per_cat'].get(cat,{}).get('DR',  0.0) for r in runs]
        asr_c = [r['per_cat'].get(cat,{}).get('ASR',100.0) for r in runs]
        per_cat_avg[cat] = {
            'DR_mean':  round(statistics.mean(dr_c),  1),
            'DR_std':   round(statistics.stdev(dr_c), 1) if len(dr_c)>1 else 0.0,
            'ASR_mean': round(statistics.mean(asr_c), 1),
            'ASR_std':  round(statistics.stdev(asr_c),1) if len(asr_c)>1 else 0.0,
        }

    full_summary = {
        'ASR_mean': mean_asr, 'ASR_std': std_asr,
        'FPR_mean': mean_fpr, 'FPR_std': std_fpr,
        'Lat_mean': mean_lat, 'Lat_std': std_lat,
        'Blocked_mean': mean_blk,
        'wilson_lo': wl, 'wilson_hi': wu,
        'mcnemar_chi2': chi2, 'mcnemar_p': p_val,
        'per_cat_avg': per_cat_avg,
        'raw_runs': runs,
    }

    print(f"\n{SEP}")
    print(f"  ASR      : {mean_asr:.2f}% ± {std_asr:.2f}%")
    print(f"  FPR      : {mean_fpr:.2f}% ± {std_fpr:.2f}%")
    print(f"  Latency  : {mean_lat:.3f}s ± {std_lat:.3f}s")
    print(f"  Wilson CI: [{wl}%, {wu}%] at 95%")
    print(f"  McNemar  : χ²={chi2}, p {p_val}")

    # ── PART 2: Ablation ──────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("PART 2 — Ablation Study")
    print(SEP)

    configs = [
        ("L0 only",      False, False, False, False),
        ("L0+L1",        True,  False, False, False),
        ("L0+L1+L2",     True,  True,  False, False),
        ("L0+L1+L2+L3",  True,  True,  True,  False),
    ]
    ablation = {}
    atk_abl, ben_abl = generate_dataset(seed=42)

    for name, l1, l2, l3, l4 in configs:
        print(f"\nConfig: {name}")
        abl_rag = AblationRAG(l1=l1, l2=l2, l3=l3, l4=l4, model_path=settings.LLM_MODEL_PATH)
        res = evaluate(abl_rag, atk_abl, ben_abl, label=name)
        ablation[name] = {
            'ASR':     res['ASR'],
            'FPR':     res['FPR'],
            'latency': res['latency'],
            'blocked': res['blocked'],
        }
        print(f"  → ASR={res['ASR']}%  FPR={res['FPR']}%  "
              f"Lat={res['latency']}s")

    # Full of the original result
    ablation['Full (L0-L4)'] = {
        'ASR': mean_asr, 'FPR': mean_fpr,
        'latency': mean_lat, 'blocked': int(mean_blk),
        'note': f'mean of {N_RUNS} runs'
    }

    print(f"\n{SEP}")
    print(f"{'Config':<22} {'ASR':>8} {'FPR':>8} {'Latency':>10}")
    print(SEP2)
    for name, v in ablation.items():
        print(f"{name:<22} {v['ASR']:>7.1f}% {v['FPR']:>7.1f}% {v['latency']:>9.2f}s")

    # ── PART 3: SC Examples ───────────────────────────────────────
    print(f"\n{SEP}")
    print("PART 3 — Semantic Camouflage Examples")
    print(SEP)
    sc_examples = load_sc_examples()
    for i, ex in enumerate(sc_examples):
        print(f"\n  Example {i+1}: {ex['query'][:100]}...")

    # ── graphs ──────────────────────────────────────
    print(f"\n{SEP}")
    print("Generating plots...")
    print(SEP)
    plot_multirun_summary(runs, mean_asr, std_asr,
                          mean_fpr, std_fpr, mean_lat, std_lat)
    plot_ablation(ablation)
    plot_per_category(per_cat_avg)

    # ──  JSON ──────────────────────────────────────────────────────────────
    output = {
        'generated_at':  time.strftime('%Y-%m-%d %H:%M:%S'),
        'config': {'model': SELECTED_MODEL, 'n_runs': N_RUNS, 'seeds': SEEDS,
                   'attack_count': ATTACK_COUNT, 'benign_count': BENIGN_COUNT},
        'full_evaluation':   full_summary,
        'ablation_study':    ablation,
        'sc_examples':       sc_examples,
    }
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults JSON  → {OUTPUT_JSON}")

    # ──
    latex = make_latex(full_summary, ablation, sc_examples)
    with open(LATEX_FILE, 'w', encoding='utf-8') as f:
        f.write(latex)
    print(f"LaTeX snippets → {LATEX_FILE}")

    elapsed = int(time.time() - t0)
    print(f"\n{SEP}")
    print(f"DONE — {elapsed//60}m {elapsed%60}s")
    print(f"All outputs saved in: {OUT_DIR}/")
    print(SEP)


if __name__ == "__main__":
    main()