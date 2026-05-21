import matplotlib.pyplot as plt
import numpy as np
import os

os.makedirs('outputs', exist_ok=True)
plt.rcParams['font.family'] = 'Arial'
plt.rcParams['font.size'] = 12
plt.style.use('seaborn-v0_8-whitegrid')

# ── Figure 1: Baseline vs SecureRAG ─────────────────────────
fig, axes = plt.subplots(1, 3, figsize=(15, 5))
fig.suptitle('Figure 4.1: SecureRAG vs Undefended Baseline (N=1,000 attacks)',
             fontsize=14, fontweight='bold', y=1.02)

axes[0].bar(['Baseline', 'SecureRAG'], [100, 43.2],
            color=['#e74c3c', '#2ecc71'], edgecolor='black', linewidth=0.8)
axes[0].set_title('Attack Success Rate (ASR %)\nLower is Better ↓', fontweight='bold')
axes[0].set_ylabel('ASR (%)')
axes[0].set_ylim(0, 115)
for i, v in enumerate([100, 43.2]):
    axes[0].text(i, v+2, f'{v}%', ha='center', fontweight='bold', fontsize=13)

axes[1].bar(['Baseline', 'SecureRAG'], [0, 0],
            color=['#e74c3c', '#2ecc71'], edgecolor='black', linewidth=0.8)
axes[1].set_title('False Positive Rate (FPR %)\nLower is Better ↓', fontweight='bold')
axes[1].set_ylabel('FPR (%)')
axes[1].set_ylim(0, 10)
for i, v in enumerate([0, 0]):
    axes[1].text(i, v+0.3, f'{v}%', ha='center', fontweight='bold', fontsize=13)

axes[2].bar(['Baseline', 'SecureRAG'], [0.82, 0.82],
            color=['#e74c3c', '#2ecc71'], edgecolor='black', linewidth=0.8)
axes[2].set_title('Response Quality\n(Relevance Score)', fontweight='bold')
axes[2].set_ylabel('Score (0-1)')
axes[2].set_ylim(0, 1.1)
for i, v in enumerate([0.82, 0.82]):
    axes[2].text(i, v+0.02, f'{v}', ha='center', fontweight='bold', fontsize=13)

plt.tight_layout()
plt.savefig('outputs/fig1_baseline_vs_securerag.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Figure 1 saved")

# ── Figure 2: Layer Breakdown ────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(13, 5))
fig.suptitle('Figure 4.2: Defense Layer Contribution Analysis',
             fontsize=14, fontweight='bold')

sizes   = [284, 139, 3]
labels  = ['L2 Rules\n284 (66.7%)', 'L1 Sanitization\n139 (32.6%)', 'L3 Anomaly\n3 (0.7%)']
colors  = ['#3498db', '#e67e22', '#9b59b6']
axes[0].pie(sizes, explode=(0.05,0.05,0.1), labels=labels, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90,
            textprops={'fontsize':11})
axes[0].set_title('Attacks Blocked by Layer (N=426)', fontweight='bold')

bars = axes[1].bar(['L1\nSanitization','L2\nRules','L3\nAnomaly'],
                   [139,284,3], color=['#e67e22','#3498db','#9b59b6'],
                   edgecolor='black', linewidth=0.8, width=0.5)
axes[1].set_title('Attacks Blocked per Layer', fontweight='bold')
axes[1].set_ylabel('Attacks Blocked')
axes[1].set_ylim(0, 330)
for bar, val in zip(bars, [139,284,3]):
    axes[1].text(bar.get_x()+bar.get_width()/2, val+5,
                str(val), ha='center', fontweight='bold', fontsize=13)

plt.tight_layout()
plt.savefig('outputs/fig2_layer_breakdown.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Figure 2 saved")

# ── Figure 3: Ablation Study ─────────────────────────────────
fig, ax = plt.subplots(figsize=(11, 6))
fig.suptitle('Figure 4.3: Ablation Study — Contribution of Each Defense Layer',
             fontsize=14, fontweight='bold')

configs   = ['No Defense', 'L1 Only\n(Sanitization)', 'L1+L2\n(+Rules)', 'Full SecureRAG\n(L1+L2+L3)']
asr_vals  = [100, 59.5, 33.0, 32.0]
dr_vals   = [0,   40.5, 67.0, 68.0]
x = np.arange(len(configs))
w = 0.35

bars1 = ax.bar(x-w/2, asr_vals, w, label='ASR (%)',
               color='#e74c3c', edgecolor='black', linewidth=0.8)
bars2 = ax.bar(x+w/2, dr_vals,  w, label='Detection Rate (%)',
               color='#2ecc71', edgecolor='black', linewidth=0.8)

for bar, val in zip(bars1, asr_vals):
    ax.text(bar.get_x()+bar.get_width()/2, val+1.5,
            f'{val}%', ha='center', fontsize=10, fontweight='bold', color='#c0392b')
for bar, val in zip(bars2, dr_vals):
    ax.text(bar.get_x()+bar.get_width()/2, val+1.5,
            f'{val}%', ha='center', fontsize=10, fontweight='bold', color='#27ae60')

ax.set_ylabel('Percentage (%)')
ax.set_xticks(x)
ax.set_xticklabels(configs, fontsize=11)
ax.set_ylim(0, 115)
ax.legend(fontsize=12)
ax.axhline(y=50, color='gray', linestyle='--', alpha=0.4)

plt.tight_layout()
plt.savefig('outputs/fig3_ablation_study.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Figure 3 saved")

# ── Figure 4: Comparison with Liu et al. ────────────────────
fig, axes = plt.subplots(1, 2, figsize=(13, 6))
fig.suptitle('Figure 4.4: SecureRAG vs Sandwich Defense (Liu et al., USENIX 2024)',
             fontsize=14, fontweight='bold')

systems     = ['No Defense', 'Sandwich Defense\n(Liu et al. 2024)', 'SecureRAG\n(This Work)']
asr_c       = [100, 66, 30]
dr_c        = [0,   34, 70]
colors_sys  = ['#95a5a6', '#f39c12', '#2ecc71']

bars = axes[0].bar(systems, asr_c, color=colors_sys, edgecolor='black', linewidth=0.8)
axes[0].set_title('Attack Success Rate (%)\nLower is Better ↓', fontweight='bold')
axes[0].set_ylabel('ASR (%)')
axes[0].set_ylim(0, 115)
for bar, val in zip(bars, asr_c):
    axes[0].text(bar.get_x()+bar.get_width()/2, val+2,
                f'{val}%', ha='center', fontweight='bold', fontsize=12)

bars2 = axes[1].bar(systems, dr_c, color=colors_sys, edgecolor='black', linewidth=0.8)
axes[1].set_title('Detection Rate (%)\nHigher is Better ↑', fontweight='bold')
axes[1].set_ylabel('Detection Rate (%)')
axes[1].set_ylim(0, 85)
for bar, val in zip(bars2, dr_c):
    axes[1].text(bar.get_x()+bar.get_width()/2, val+1.5,
                f'{val}%', ha='center', fontweight='bold', fontsize=12)

axes[1].annotate('', xy=(2,70), xytext=(1,34),
                arrowprops=dict(arrowstyle='->', color='#27ae60', lw=2.5))
axes[1].text(1.55, 55, '+36%', color='#27ae60', fontweight='bold', fontsize=13)

plt.tight_layout()
plt.savefig('outputs/fig4_comparison_liu2024.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Figure 4 saved")

# ── Figure 5: Attack Categories (Real Data) ──────────────────
fig, ax = plt.subplots(figsize=(14, 6))
fig.suptitle('Figure 4.5: SecureRAG Detection Rate by Attack Category (Real Data)',
             fontsize=14, fontweight='bold')

categories = ['context\npoisoning\n(n=117)', 'indirect\npoisoning\n(n=112)',
              'psychological\nmanip\n(n=93)', 'nested\nhiding\n(n=98)',
              'token\nsmuggling\n(n=98)', 'trust\nescalation\n(n=73)',
              'conversational\ndrift\n(n=81)', 'semantic\ncamouflage\n(n=78)']
dr_real    = [72.6, 69.6, 71.0, 66.3, 60.2, 57.5, 22.2, 16.7]
asr_real   = [27.4, 30.4, 29.0, 33.7, 39.8, 42.5, 77.8, 83.3]

x = np.arange(len(categories))
bars_b = ax.bar(x, dr_real,  label='Blocked (DR%)', color='#2ecc71',
                edgecolor='black', linewidth=0.8)
bars_p = ax.bar(x, asr_real, bottom=dr_real, label='Bypassed (ASR%)',
                color='#e74c3c', edgecolor='black', linewidth=0.8)

for i, (b, p) in enumerate(zip(dr_real, asr_real)):
    if b > 8:
        ax.text(i, b/2, f'{b:.0f}%', ha='center', va='center',
                fontweight='bold', fontsize=9, color='white')
    ax.text(i, b+p/2, f'{p:.0f}%', ha='center', va='center',
            fontweight='bold', fontsize=9, color='white')

ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=9)
ax.set_ylabel('Percentage of Attacks (%)')
ax.set_ylim(0, 110)
ax.legend(fontsize=12, loc='upper right')
ax.axhline(y=50, color='black', linestyle='--', alpha=0.3)

plt.tight_layout()
plt.savefig('outputs/fig5_attack_categories.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Figure 5 saved")

print("\n🎉 All 5 figures saved in outputs/")