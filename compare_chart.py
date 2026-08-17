#!/usr/bin/env python3
"""
compare_chart.py
-----------------
Bar-chart comparison: Internal (self-generated, 1,001 attacks) vs
BIPIA External Validation (986 attacks).

Usage:
    python3 compare_chart.py
Output:
    comparison_chart.png
"""

import matplotlib
matplotlib.use("Agg")  # safe backend, no display needed
import matplotlib.pyplot as plt
import numpy as np

# ── Data: edit these if your numbers change ──────────────────────────
labels = ["ASR (%)", "Detection Rate (%)", "FPR (%)", "Avg Latency (s)"]

internal = [8.96, 91.04, 0.00, 6.09]
external = [16.23, 83.77, None, 12.20]  # FPR not measured externally (no legit-query set)

# ── Plot ───────────────────────────────────────────────────────────
x = np.arange(len(labels))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5.5))

bars1 = ax.bar(x - width/2, internal, width, label="Internal (n=1,001)", color="#2E86AB")
external_plot = [v if v is not None else 0 for v in external]
bars2 = ax.bar(x + width/2, external_plot, width, label="BIPIA External (n=986)", color="#E76F51")

for bars, values in [(bars1, internal), (bars2, external)]:
    for bar, val in zip(bars, values):
        if val is None:
            ax.text(bar.get_x() + bar.get_width()/2, 1, "N/A",
                     ha="center", va="bottom", fontsize=9, color="gray")
            continue
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f"{val:.2f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

ax.set_ylabel("Value")
ax.set_title("SecureRAG: Internal vs. BIPIA External Validation")
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.set_ylim(0, max([v for v in internal + external if v is not None]) * 1.25)

plt.tight_layout()
plt.savefig("comparison_chart.png", dpi=200)
print("Saved: comparison_chart.png")