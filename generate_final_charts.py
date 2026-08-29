#!/usr/bin/env python3
"""generate_final_charts.py -------------------------- Regenerates every reporting chart from REAL."""

import argparse
import csv
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Same palette as thesis_evaluation.py's own plots, for visual consistency.
plt.rcParams.update({'axes.facecolor': '#f9f9f9'})
C_SAFE, C_DANGER, C_NEUTRAL, C_ACCENT = '#6b9e8a', '#c0392b', '#5c7a9e', '#e67e22'

def load_json(path):
    if not path or not Path(path).exists():
        return None
    return json.load(open(path, encoding="utf-8"))

def load_compliance_csv(path):
    if not path or not Path(path).exists():
        return None
    return list(csv.DictReader(open(path, encoding="utf-8")))

def savefig(fig, out_dir, name):
    out_path = Path(out_dir) / name
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved -> {out_path}")

def chart_ablation(thesis, out_dir):
    """01 -- rebuild of the (already-correct) ablation chart, from the same thesis_results.json, so it."""
    abl = thesis["ablation_study"]
    names = ["L0 only", "L0+L1", "L0+L1+L2", "L0+L1+L2+L3", "Full (L0-L4)"]
    names = [n for n in names if n in abl]
    asr = [abl[n]["ASR"] for n in names]
    fpr = [abl[n]["FPR"] for n in names]
    lat = [abl[n]["latency"] for n in names]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5))
    fig.suptitle("Ablation Study -- Cumulative Layer Contribution", fontweight="bold", fontsize=14)

    x = np.arange(len(names))
    ax1.bar(x - 0.2, asr, 0.4, label="ASR (%)", color=C_DANGER)
    ax1.bar(x + 0.2, fpr, 0.4, label="FPR (%)", color=C_SAFE)
    for i, v in enumerate(asr):
        ax1.text(i - 0.2, v + 1, f"{v:.1f}%", ha="center", fontweight="bold", color=C_DANGER, fontsize=9)
    for i, v in enumerate(fpr):
        ax1.text(i + 0.2, v + 1, f"{v:.1f}%", ha="center", fontweight="bold", color=C_SAFE, fontsize=9)
    ax1.set_xticks(x); ax1.set_xticklabels(names, rotation=15, ha="right")
    ax1.set_ylabel("Rate (%)")
    ax1.set_title("ASR and FPR by Configuration\n(Lower is better for both)")
    ax1.legend()

    ax2.plot(x, lat, "o-", color=C_ACCENT, linewidth=2)
    for i, v in enumerate(lat):
        ax2.annotate(f"{v:.2f}s", (i, v), textcoords="offset points", xytext=(0, 8), ha="center")
    ax2.set_xticks(x); ax2.set_xticklabels(names, rotation=15, ha="right")
    ax2.set_ylabel("Avg Latency (s)")
    ax2.set_title("Average Query Latency by Configuration\n(More layers = earlier blocking = lower latency)")

    plt.tight_layout()
    savefig(fig, out_dir, "01_ablation_study.png")

def chart_multirun(thesis, out_dir):
    """02 -- per-seed ASR/FPR/latency, straight from raw_runs (no re-derivation)."""
    runs = thesis["full_evaluation"]["raw_runs"]
    n = len(runs)
    labels = [f"Run {i+1}" for i in range(n)]
    asr = [r["ASR"] for r in runs]
    fpr = [r["FPR"] for r in runs]
    lat = [r["latency"] for r in runs]
    ma, sa = thesis["full_evaluation"]["ASR_mean"], thesis["full_evaluation"]["ASR_std"]
    mf = thesis["full_evaluation"]["FPR_mean"]
    ml, sl = thesis["full_evaluation"]["Lat_mean"], thesis["full_evaluation"]["Lat_std"]

    fig, axes = plt.subplots(1, 3, figsize=(15, 5.5))
    fig.suptitle(f"SecureRAG Multi-Run Evaluation Summary (N={n} independent runs)", fontweight="bold", fontsize=13)

    axes[0].bar(labels, asr, color=C_DANGER, alpha=0.8)
    axes[0].axhline(ma, ls="--", color="black", label=f"Mean = {ma:.1f}%")
    axes[0].fill_between(range(n), ma - sa, ma + sa, alpha=0.15, color="black")
    for i, v in enumerate(asr):
        axes[0].text(i, v + 0.15, f"{v:.1f}%", ha="center", fontsize=9)
    axes[0].set_title("Attack Success Rate (ASR %)\nLower is better ↓", fontweight="bold")
    axes[0].legend()

    axes[1].bar(labels, fpr, color=C_SAFE, alpha=0.8)
    axes[1].axhline(mf, ls="--", color="black", label=f"Mean = {mf:.2f}%")
    for i, v in enumerate(fpr):
        axes[1].text(i, v + 0.02, f"{v:.1f}%", ha="center", fontsize=9)
    axes[1].set_title("False Positive Rate (FPR %)\nLower is better ↓", fontweight="bold")
    axes[1].legend()

    axes[2].bar(labels, lat, color=C_NEUTRAL, alpha=0.8)
    axes[2].axhline(ml, ls="--", color="black", label=f"Mean = {ml:.2f}s")
    for i, v in enumerate(lat):
        axes[2].text(i, v + 0.05, f"{v:.2f}s", ha="center", fontsize=9)
    axes[2].set_title("Avg Query Latency (s)", fontweight="bold")
    axes[2].legend()

    plt.tight_layout()
    savefig(fig, out_dir, "02_multirun_summary.png")

def chart_per_category(thesis, out_dir):
    """03 -- per-category DR/ASR mean+-std, straight from per_cat_avg."""
    cats = thesis["full_evaluation"]["per_cat_avg"]
    names = sorted(cats.keys())
    dr = [cats[c]["DR_mean"] for c in names]
    dr_std = [cats[c]["DR_std"] for c in names]
    asr = [cats[c]["ASR_mean"] for c in names]
    colors = [C_SAFE if d >= 80 else ("#e8a33d" if d >= 50 else C_DANGER) for d in dr]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(names, dr, yerr=dr_std, capsize=4, color=colors)
    for i, (d, a) in enumerate(zip(dr, asr)):
        ax.text(i, d + dr_std[i] + 2, f"DR={d:.0f}%\nASR={a:.0f}%", ha="center", fontsize=9, fontweight="bold")
    ax.axhline(80, ls="--", color="gray", alpha=0.6)
    ax.set_ylabel("Detection Rate (%)")
    ax.set_title("Detection Rate by Attack Category\n(mean ± std across independent runs)", fontweight="bold")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    savefig(fig, out_dir, "03_detection_by_category.png")

def chart_confusion_matrix(thesis, out_dir):
    """04 -- built from the FIRST logged run (labelled by its real seed, not assumed to be 42), using."""
    cfg = thesis["config"]
    run0 = thesis["full_evaluation"]["raw_runs"][0]
    seed0 = cfg["seeds"][0]
    n_atk, n_ben = cfg["attack_count"], cfg["benign_count"]
    tp, fp = run0["blocked"], run0["fp"]
    fn, tn = n_atk - tp, n_ben - fp

    fig, ax = plt.subplots(figsize=(6.5, 6.5))
    grid = np.array([[tp, fn], [fp, tn]])
    ax.imshow(grid, cmap="Blues", vmin=0, vmax=max(tp, n_ben))
    labels = [["True Positive", "False Negative"], ["False Positive", "True Negative"]]
    for i in range(2):
        for j in range(2):
            txt_color = "white" if (i, j) in [(0, 0), (1, 1)] else "black"
            ax.text(j, i - 0.08, f"{grid[i,j]}", ha="center", va="center", fontsize=26, fontweight="bold", color=txt_color)
            ax.text(j, i + 0.18, labels[i][j], ha="center", va="center", fontsize=11, style="italic",
                    color="#dddddd" if (i, j) in [(0, 0), (1, 1)] else "#555555")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Blocked\n(TP / FP)", "Passed\n(FN / TN)"], fontweight="bold")
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Attack", "Benign"], fontweight="bold", rotation=90, va="center")
    ax.set_xlabel("SecureRAG Decision", fontweight="bold")
    ax.set_ylabel("True Label", fontweight="bold")
    ax.set_title("Defense Confusion Matrix", fontweight="bold", fontsize=15)
    fig.text(0.5, 0.01, f"Seed = {seed0} (Run 1 of {cfg['n_runs']})  ·  {n_atk} attack queries  ·  {n_ben} legitimate queries",
              ha="center", fontsize=9, style="italic", color="#666666")
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    savefig(fig, out_dir, "04_confusion_matrix.png")

def chart_layer_effectiveness(thesis, out_dir, layer_measurement=None):
    """05 -- PREFERS a real, direct per-query measurement (produced by measure_layer_effectiveness.py."""
    layer_names = ["L1\nSanitization", "L2\nRules", "L3\nAnomaly", "L4\nSemantic"]

    if layer_measurement is not None:
        c = layer_measurement["layer_counts"]
        if c.get("other"):
            raise SystemExit(
                f"\n  05_layer_effectiveness: this measurement JSON has "
                f"other={c['other']} unbucketed blocks -- it was produced by the "
                f"old, buggy bucketing and its L2 figure is wrong.\n"
                f"  Fix it without re-running the model:\n"
                f"      python3 measure_layer_effectiveness.py --from-json <that file>.json\n"
                f"  then re-run this script.")
        deltas = [c["L1"], c["L2"], c["L3"], c["L4"]]
        subtitle = (f"direct per-query measurement, seed={layer_measurement['seed']}, "
                    f"n={layer_measurement['n_attacks']} -- measure_layer_effectiveness.py")
    else:
        abl = thesis["ablation_study"]
        run0 = thesis["full_evaluation"]["raw_runs"][0]
        order = ["L0 only", "L0+L1", "L0+L1+L2", "L0+L1+L2+L3"]
        if not all(k in abl for k in order):
            print("  skip 05_layer_effectiveness.png -- ablation_study missing expected configs")
            return
        b = [abl[k]["blocked"] for k in order] + [run0["blocked"]]
        deltas = [b[i+1] - b[i] for i in range(len(b) - 1)]
        subtitle = "marginal contribution DERIVED from the ablation study (no direct measurement supplied)"

    fig, ax = plt.subplots(figsize=(8, 5.5))
    bars = ax.bar(layer_names, deltas, color=[C_NEUTRAL, C_NEUTRAL, "#93a8bd", "#93a8bd"])
    for bar, v in zip(bars, deltas):
        ax.text(bar.get_x() + bar.get_width()/2, v + max(deltas)*0.02, f"{v}", ha="center", fontweight="bold", fontsize=13)
    ax.set_ylabel("Attacks Blocked")
    ax.set_title(f"Defense Layer Effectiveness\n{subtitle}", fontweight="bold", fontsize=11)
    plt.tight_layout()
    savefig(fig, out_dir, "05_layer_effectiveness.png")

def chart_latency_baseline(thesis, out_dir):
    """06 -- baseline = 'L0 only' config (nothing blocks -> every query reaches the LLM, the real."""
    abl = thesis["ablation_study"]
    if "L0 only" not in abl:
        print("  skip 06_latency_baseline.png -- 'L0 only' missing from ablation_study")
        return
    baseline = abl["L0 only"]["latency"]
    secure = thesis["full_evaluation"]["Lat_mean"]
    secure_std = thesis["full_evaluation"]["Lat_std"]
    reduction = 100 * (baseline - secure) / baseline

    fig, ax = plt.subplots(figsize=(7, 6))
    bars = ax.bar(["Baseline\n(No Defense)", "SecureRAG\n(5-Layer)"], [baseline, secure],
                   color=[C_NEUTRAL, C_SAFE], yerr=[0, secure_std], capsize=6)
    ax.text(0, baseline + 0.4, f"{baseline:.2f}s", ha="center", fontsize=16, fontweight="bold")
    ax.text(0, baseline + 1.6, "Every query reaches LLM\n(including malicious ones)", ha="center", fontsize=9,
            style="italic", color="#5c7a9e")
    ax.text(1, secure + secure_std + 0.4, f"{secure:.2f}s", ha="center", fontsize=16, fontweight="bold")
    ax.text(1, secure + secure_std + 1.6, f"Mean across {thesis['config']['n_runs']} runs\n(±{secure_std:.2f}s std)",
            ha="center", fontsize=9, style="italic", color=C_SAFE)
    ax.annotate("", xy=(1, secure), xytext=(1, baseline),
                arrowprops=dict(arrowstyle="->", color=C_DANGER, lw=2))
    ax.text(1.25, (baseline + secure) / 2, f"−{reduction:.1f}%", color=C_DANGER, fontweight="bold", fontsize=13)
    ax.set_ylabel("Average Latency (seconds)")
    ax.set_title("Response Latency: Baseline vs SecureRAG", fontweight="bold")
    ax.set_ylim(0, baseline * 1.25)
    plt.tight_layout()
    savefig(fig, out_dir, "06_latency_baseline_vs_securerag.png")

def chart_internal_vs_external_asr(thesis, ext_summary, compliance_rows, out_dir):
    """07 -- ASR comparison ONLY (kept separate from FPR per your request)."""
    if ext_summary is None:
        print("  skip 07_internal_vs_external_ASR.png -- no --external-summary file given")
        return
    internal_asr = thesis["full_evaluation"]["ASR_mean"]
    internal_std = thesis["full_evaluation"]["ASR_std"]
    external_raw = ext_summary["asr_external_pct"]
    n_ext = ext_summary["n_samples"]

    labels = ["Internal\n(self-generated)", "External\n(BIPIA, reached-model proxy)"]
    values = [internal_asr, external_raw]
    errs = [internal_std, 0]
    colors = [C_DANGER, "#d98c6b"]

    if compliance_rows:
        n_complied = sum(1 for r in compliance_rows if r.get("verdict") == "likely_complied")
        true_asr = 100 * n_complied / n_ext
        labels.append("External\n(BIPIA, true compliance)")
        values.append(true_asr)
        errs.append(0)
        colors.append(C_DANGER)

    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(labels, values, yerr=errs, capsize=6, color=colors)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, v + 1.5, f"{v:.2f}%", ha="center", fontweight="bold", fontsize=13)
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Internal vs. External (BIPIA) Attack Success Rate", fontweight="bold")
    ax.set_ylim(0, max(values) * 1.25)
    if compliance_rows:
        ax.annotate("'reached model' ≠ 'complied' -- see classify_true_compliance.py",
                    xy=(1, external_raw), xytext=(0.5, max(values) * 1.12),
                    fontsize=8, color="#888888", ha="center")
    plt.tight_layout()
    savefig(fig, out_dir, "07_internal_vs_external_ASR.png")

def chart_internal_vs_external_fpr(thesis, ext_fpr_summary, out_dir):
    """08 -- FPR comparison ONLY (separate chart from ASR, as requested)."""
    if ext_fpr_summary is None:
        print("  skip 08_internal_vs_external_FPR.png -- no --external-fpr-summary file given yet")
        return
    internal_fpr = thesis["full_evaluation"]["FPR_mean"]
    internal_std = thesis["full_evaluation"]["FPR_std"]
    external_fpr = ext_fpr_summary["false_positive_rate_pct"]

    fig, ax = plt.subplots(figsize=(6.5, 6))
    bars = ax.bar(["Internal\n(self-generated)", "External\n(BIPIA)"],
                   [internal_fpr, external_fpr], yerr=[internal_std, 0], capsize=6,
                   color=[C_SAFE, "#8bb89e"])
    for bar, v in zip(bars, [internal_fpr, external_fpr]):
        ax.text(bar.get_x() + bar.get_width()/2, v + max(internal_fpr, external_fpr)*0.05,
                 f"{v:.2f}%", ha="center", fontweight="bold", fontsize=13)
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("Internal vs. External (BIPIA) False Positive Rate", fontweight="bold")
    ax.set_ylim(0, max(internal_fpr, external_fpr) * 1.6 + 0.5)
    plt.tight_layout()
    savefig(fig, out_dir, "08_internal_vs_external_FPR.png")

def _mstats(t):
    fe = t["full_evaluation"]
    return fe["ASR_mean"], fe["ASR_std"], fe["FPR_mean"], fe["FPR_std"], fe["Lat_mean"], fe["Lat_std"]

def chart_cmp_internal(models, out_dir):
    """09 -- internal ASR / FPR / latency side by side, with error bars."""
    names = list(models)
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.2))
    fig.suptitle("Internal evaluation across models (5 seeds each, identical code and seeds)",
                 fontweight="bold", fontsize=13)
    metrics = [("Attack Success Rate (%)", 0, 1, C_DANGER, "Lower is better ↓"),
               ("False Positive Rate (%)", 2, 3, C_SAFE, "Lower is better ↓"),
               ("Mean latency (s)", 4, 5, C_NEUTRAL, "Lower is better ↓")]
    for ax, (title, mi, si, colour, sub) in zip(axes, metrics):
        vals = [_mstats(models[n])[mi] for n in names]
        errs = [_mstats(models[n])[si] for n in names]
        ax.bar(names, vals, yerr=errs, capsize=6, color=colour, alpha=0.85)
        for i, (v, e) in enumerate(zip(vals, errs)):
            ax.text(i, v + e + max(vals) * 0.04, f"{v:.2f}", ha="center",
                    fontweight="bold", fontsize=11)
        ax.set_title(f"{title}\n{sub}", fontweight="bold")
        ax.set_ylim(0, max(v + e for v, e in zip(vals, errs)) * 1.28)
    plt.tight_layout()
    savefig(fig, out_dir, "09_cross_model_internal.png")

def chart_cmp_external(models, ext, ext_fpr, comp, out_dir):
    """10 -- external detection / reach-rate ASR / true-compliance ASR / FPR."""
    names = [n for n in models if ext.get(n)]
    if len(names) < 2:
        print("  skip 10_cross_model_external.png -- need external summaries for two models")
        return
    det = [ext[n]["detection_rate_pct"] for n in names]
    reach = [ext[n]["asr_external_pct"] for n in names]
    true_asr, fpr = [], []
    for n in names:
        rows = comp.get(n)
        nt = ext[n]["n_samples"]
        true_asr.append(100 * sum(1 for r in rows if r.get("verdict") == "likely_complied") / nt
                        if rows else None)
        fpr.append(ext_fpr[n]["false_positive_rate_pct"] if ext_fpr.get(n) else None)

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.suptitle("External validation across models — BIPIA (Microsoft), 986 attacks each",
                 fontweight="bold", fontsize=13)
    x = np.arange(len(names)); w = 0.26
    ax = axes[0]
    ax.bar(x - w, det, w, label="Detection rate", color=C_SAFE)
    ax.bar(x, reach, w, label="ASR (reached model)", color="#d98c6b")
    if all(v is not None for v in true_asr):
        ax.bar(x + w, true_asr, w, label="ASR (true compliance)", color=C_DANGER)
    for i, trio in enumerate(zip(det, reach, true_asr)):
        for off, v in zip((-w, 0, w), trio):
            if v is not None:
                ax.text(i + off, v + 1.5, f"{v:.1f}", ha="center", fontsize=9, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(names)
    ax.set_ylabel("%"); ax.set_title("Attack side", fontweight="bold")
    ax.legend(fontsize=9); ax.set_ylim(0, 70)

    ax = axes[1]
    if all(v is not None for v in fpr):
        ax.bar(names, fpr, color=C_SAFE, alpha=0.85, width=0.45)
        for i, v in enumerate(fpr):
            ax.text(i, v + max(fpr) * 0.04, f"{v:.2f}%", ha="center", fontweight="bold", fontsize=12)
        ax.set_ylim(0, max(fpr) * 1.3)
    ax.set_ylabel("False positive rate (%)")
    ax.set_title("Benign side (333 clean BIPIA documents)", fontweight="bold")
    plt.tight_layout()
    savefig(fig, out_dir, "10_cross_model_external.png")

def chart_cmp_layers(models, ext, ext_fpr, out_dir):
    """11 -- the architectural result: every cross-model difference sits in L4."""
    names = [n for n in models if ext.get(n) and ext_fpr.get(n)]
    if len(names) < 2:
        print("  skip 11_cross_model_layers.png -- need external + FPR summaries for two models")
        return
    keymap = {"rules": "L2 rules", "anomaly": "L3 anomaly", "semantic": "L4 semantic"}
    order = list(keymap)
    atk = {n: [ext[n]["layer_distribution"].get(k, 0) for k in order] for n in names}
    ben = {n: [ext_fpr[n]["layer_distribution"].get(k, 0) for k in order] for n in names}

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.suptitle("Where the two models differ: only L4 — every other layer is identical",
                 fontweight="bold", fontsize=13)
    for ax, data, title, ylab in [
            (axes[0], atk, "Attacks blocked (986 samples)", "attacks blocked"),
            (axes[1], ben, "False positives (333 benign samples)", "benign wrongly blocked")]:
        x = np.arange(len(order)); w = 0.35
        for i, n in enumerate(names):
            bars = ax.bar(x + (i - 0.5) * w, data[n], w, label=n,
                          color=[C_NEUTRAL, C_ACCENT][i % 2], alpha=0.9)
            for b, v in zip(bars, data[n]):
                ax.text(b.get_x() + b.get_width() / 2, v + max(max(data.values(), key=max)) * 0.02,
                        str(v), ha="center", fontsize=9, fontweight="bold")
        for j, k in enumerate(order):
            vals = [data[n][j] for n in names]
            if len(set(vals)) == 1:
                ax.text(j, -max(max(data.values(), key=max)) * 0.09, "identical",
                        ha="center", fontsize=9, style="italic", color=C_SAFE, fontweight="bold")
        ax.set_xticks(x); ax.set_xticklabels([keymap[k] for k in order])
        ax.set_ylabel(ylab); ax.set_title(title, fontweight="bold")
        ax.legend(fontsize=9)
    plt.tight_layout()
    savefig(fig, out_dir, "11_cross_model_layers.png")

def chart_cmp_categories(models, out_dir):
    """12 -- internal per-tier detection, both models on one axis."""
    names = list(models)
    cats = sorted(models[names[0]]["full_evaluation"]["per_cat_avg"])
    fig, ax = plt.subplots(figsize=(13, 6))
    x = np.arange(len(cats)); w = 0.35
    for i, n in enumerate(names):
        pc = models[n]["full_evaluation"]["per_cat_avg"]
        v = [pc[c]["DR_mean"] for c in cats]
        e = [pc[c]["DR_std"] for c in cats]
        ax.bar(x + (i - 0.5) * w, v, w, yerr=e, capsize=3, label=n,
               color=[C_SAFE, C_NEUTRAL][i % 2], alpha=0.9)
    ax.axhline(80, ls="--", color="gray", alpha=0.6)
    ax.set_xticks(x); ax.set_xticklabels(cats, rotation=20, ha="right")
    ax.set_ylabel("Detection rate (%)")
    ax.set_title("Detection by attack tier, both models (mean ± std over 5 seeds)",
                 fontweight="bold")
    ax.legend()
    plt.tight_layout()
    savefig(fig, out_dir, "12_cross_model_by_category.png")

def chart_cmp_compliance(models, ext, comp, out_dir):
    """13 -- what actually happened to all 986 attacks, per model."""
    names = [n for n in models if comp.get(n) and ext.get(n)]
    if not names:
        print("  skip 13_compliance_breakdown.png -- need compliance CSVs")
        return
    fig, ax = plt.subplots(figsize=(11, 5.5))
    labels = ["blocked before model", "reached, resisted", "reached, ambiguous", "reached, complied"]
    colours = [C_SAFE, "#8fbf9f", "#d9c26b", C_DANGER]
    bottoms = np.zeros(len(names))
    parts = []
    for n in names:
        rows = comp[n]; tot = ext[n]["n_samples"]
        c = sum(1 for r in rows if r.get("verdict") == "likely_complied")
        r_ = sum(1 for r in rows if r.get("verdict") == "likely_resisted")
        a = sum(1 for r in rows if r.get("verdict") == "ambiguous")
        parts.append([tot - (c + r_ + a), r_, a, c])
    parts = np.array(parts, dtype=float)
    tots = np.array([ext[n]["n_samples"] for n in names], dtype=float)
    for j, (lab, col) in enumerate(zip(labels, colours)):
        vals = 100 * parts[:, j] / tots
        ax.barh(names, vals, left=bottoms, color=col, label=lab, height=0.5)
        for i, v in enumerate(vals):
            if v > 3:
                ax.text(bottoms[i] + v / 2, i, f"{v:.1f}%", ha="center", va="center",
                        fontsize=10, fontweight="bold",
                        color="white" if j in (0, 3) else "black")
        bottoms += vals
    ax.set_xlim(0, 100); ax.set_xlabel("share of all 986 external attacks (%)")
    ax.set_title("What happened to every external attack", fontweight="bold")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=4, fontsize=9)
    plt.tight_layout()
    savefig(fig, out_dir, "13_compliance_breakdown.png")

def chart_cmp_margin(models, ext, comp, out_dir):
    """14 -- margin sensitivity, recomputed from each compliance CSV."""
    names = [n for n in models if comp.get(n) and ext.get(n)]
    if not names:
        print("  skip 14_margin_sensitivity.png -- need compliance CSVs")
        return
    margins = [0.0, 0.02, 0.05, 0.10, 0.15, 0.20]
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for i, n in enumerate(names):
        rows = comp[n]; tot = ext[n]["n_samples"]
        gaps = [float(r["attack_similarity"]) - float(r["benign_similarity"]) for r in rows]
        ys = [100 * sum(1 for g in gaps if g > m) / tot for m in margins]
        ax.plot(margins, ys, "o-", linewidth=2, label=n,
                color=[C_DANGER, C_ACCENT][i % 2])
        for m, y in zip(margins, ys):
            ax.annotate(f"{y:.1f}", (m, y), textcoords="offset points",
                        xytext=(0, 8), ha="center", fontsize=8)
        spread = max(ys) - min(ys)
        ax.plot([], [], " ", label=f"    spread: {spread:.1f} pts")
    ax.axvline(0.05, ls=":", color="gray", alpha=0.7)
    ax.annotate("reported margin (0.05)", xy=(0.05, ax.get_ylim()[1] * 0.95),
                fontsize=8, color="gray", rotation=90, va="top")
    ax.set_xlabel("classification margin"); ax.set_ylabel("true-compliance ASR (%)")
    ax.set_title("How much the compliance figure depends on the margin\n"
                 "(a flat line means the number is robust)", fontweight="bold")
    ax.legend(fontsize=9)
    plt.tight_layout()
    savefig(fig, out_dir, "14_margin_sensitivity.png")

def run():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="e.g. Mistral-7B -- used to build default file paths")
    ap.add_argument("--thesis-results", default=None)
    ap.add_argument("--external-summary", default=None)
    ap.add_argument("--external-fpr-summary", default=None)
    ap.add_argument("--compliance-csv", default=None)
    ap.add_argument("--layer-measurement", default=None,
                     help="layer_effectiveness__<model>.json produced by "
                          "measure_layer_effectiveness.py (a real per-query "
                          "measurement). If not given/found, chart 05 falls "
                          "back to deriving marginal contribution from the "
                          "ablation study instead, clearly labeled either way.")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--compare", nargs="+", metavar="MODEL", default=None,
                     help="Also build cross-model comparison charts (09-14) for these "
                          "models, e.g. --compare Mistral-7B Llama-3.2-3B. Each model's "
                          "files are located by the same naming convention used above. "
                          "Charts whose inputs are missing for either model are skipped "
                          "with a message, never filled with a placeholder.")
    args = ap.parse_args()

    m = args.model
    thesis_path = args.thesis_results or f"outputs/thesis_v2/{m}/thesis_results.json"
    ext_path = args.external_summary or f"bipia_external_summary__{m}.json"
    ext_fpr_path = args.external_fpr_summary or f"bipia_external_fpr_summary__{m}.json"
    compliance_path = args.compliance_csv or f"compliance_classified__{m}.csv"
    layer_path = args.layer_measurement or f"layer_effectiveness__{m}.json"
    out_dir = args.out_dir or f"final_charts/{m}"
    os.makedirs(out_dir, exist_ok=True)

    thesis = load_json(thesis_path)
    if thesis is None:
        print(f"ERROR: {thesis_path} not found -- this file is required (internal results).")
        return
    ext_summary = load_json(ext_path)
    ext_fpr_summary = load_json(ext_fpr_path)
    compliance_rows = load_compliance_csv(compliance_path)
    layer_measurement = load_json(layer_path)

    print(f"Model: {m}")
    print(f"  thesis-results       : {thesis_path}  (found)")
    print(f"  external-summary     : {ext_path}  ({'found' if ext_summary else 'MISSING -- chart 07 will be skipped'})")
    print(f"  external-fpr-summary : {ext_fpr_path}  ({'found' if ext_fpr_summary else 'MISSING -- chart 08 will be skipped'})")
    print(f"  compliance-csv       : {compliance_path}  ({'found' if compliance_rows else 'not found -- chart 07 will show 2 bars, not 3'})")
    print(f"  layer-measurement    : {layer_path}  ({'found -- using REAL measurement' if layer_measurement else 'not found -- chart 05 will use the ablation-derived fallback'})")
    print(f"Output folder: {out_dir}\n")

    chart_ablation(thesis, out_dir)
    chart_multirun(thesis, out_dir)
    chart_per_category(thesis, out_dir)
    chart_confusion_matrix(thesis, out_dir)
    chart_layer_effectiveness(thesis, out_dir, layer_measurement)
    chart_latency_baseline(thesis, out_dir)
    chart_internal_vs_external_asr(thesis, ext_summary, compliance_rows, out_dir)
    chart_internal_vs_external_fpr(thesis, ext_fpr_summary, out_dir)

    print(f"\nDone. Per-model charts for {m} are in: {out_dir}/")

    # ── cross-model comparison ────────────────────────────────────────────
    if args.compare:
        cmp_dir = "final_charts/comparison"
        os.makedirs(cmp_dir, exist_ok=True)
        print(f"\n{'='*62}\nCross-model comparison: {', '.join(args.compare)}\n{'='*62}")
        models, ext_all, extf_all, comp_all = {}, {}, {}, {}
        for name in args.compare:
            t = load_json(f"outputs/thesis_v2/{name}/thesis_results.json")
            if t is None:
                print(f"  ERROR: no thesis_results.json for {name} -- comparison skipped.")
                return
            models[name] = t
            ext_all[name] = load_json(f"bipia_external_summary__{name}.json")
            extf_all[name] = load_json(f"bipia_external_fpr_summary__{name}.json")
            comp_all[name] = load_compliance_csv(f"compliance_classified__{name}.csv")
            print(f"  {name:16s} internal ✓  external {'✓' if ext_all[name] else '✗'}"
                  f"  ext-FPR {'✓' if extf_all[name] else '✗'}"
                  f"  compliance {'✓' if comp_all[name] else '✗'}")
        print()
        chart_cmp_internal(models, cmp_dir)
        chart_cmp_external(models, ext_all, extf_all, comp_all, cmp_dir)
        chart_cmp_layers(models, ext_all, extf_all, cmp_dir)
        chart_cmp_categories(models, cmp_dir)
        chart_cmp_compliance(models, ext_all, comp_all, cmp_dir)
        chart_cmp_margin(models, ext_all, comp_all, cmp_dir)
        print(f"\nDone. Comparison charts are in: {cmp_dir}/")


if __name__ == "__main__":
    run()
