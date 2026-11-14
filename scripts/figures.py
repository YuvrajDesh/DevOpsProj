#!/usr/bin/env python3
"""Regenerate all figures from results/*.csv and sboms/ (no hand-entered numbers)."""
import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
sys.path.insert(0, str(Path(__file__).parent))
import normalize as N
from measure import load_tool

ROOT = Path(__file__).resolve().parent.parent
R, F = ROOT / "results", ROOT / "figures"
F.mkdir(exist_ok=True)
sns.set_theme(style="whitegrid", context="paper", font_scale=1.1)
PAL = {"syft": "#4C72B0", "trivy": "#DD8452", "cdxgen": "#55A868"}

# Fig 1: recall & precision per tool per component ecosystem (name+version, pooled)
m = pd.read_csv(R / "metrics_by_eco.csv")
m = m[m.level == "name+version"]
fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8), sharey=True)
for ax, met in zip(axes, ["recall", "precision"]):
    sns.barplot(data=m, x="eco", y=met, hue="tool", hue_order=list(PAL), palette=PAL, ax=ax)
    ax.set_ylim(0, 1.05); ax.set_xlabel("component ecosystem"); ax.set_title(met.capitalize()); ax.set_ylabel("score")
    if ax is axes[1]: ax.get_legend().remove()
    else: ax.legend(fontsize=8, loc="lower left")
fig.tight_layout(); fig.savefig(F / "fig1_recall_precision_by_eco.pdf"); fig.savefig(F / "fig1_recall_precision_by_eco.png", dpi=200)

# Fig 2: UpSet-style exclusive intersections of (image,eco,name,version) keys pooled across all 12 images
import itertools
corpus = pd.read_csv(R / "corpus.csv")
contents = {}
for t in N.TOOLS:
    s = set()
    for img in corpus.image:
        df = load_tool(t, img)
        if df is not None:
            s |= {(img, e, n, v) for e, n, v in zip(df.eco, df.name, df.version) if e != "nopurl"}
    contents[t] = s
universe = set().union(*contents.values())
regions = []
for k in range(1, 4):
    for combo in itertools.combinations(N.TOOLS, k):
        inside = set.intersection(*[contents[t] for t in combo])
        outside = set().union(*[contents[t] for t in N.TOOLS if t not in combo])
        regions.append((combo, len(inside - outside)))
regions.sort(key=lambda x: -x[1])
pd.DataFrame([dict(tools="+".join(c), exclusive_count=n) for c, n in regions]).to_csv(R / "overlap_regions.csv", index=False)
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(5.5, 3.6), sharex=True, gridspec_kw=dict(height_ratios=[3, 1.2]))
x = range(len(regions))
ax1.bar(x, [n for _, n in regions], color="#444")
for i, (_, n) in enumerate(regions):
    ax1.text(i, n, str(n), ha="center", va="bottom", fontsize=8)
ax1.set_ylabel("components"); ax1.set_title(f"Overlap of components across tools (all images, n={len(universe)})")
for j, t in enumerate(N.TOOLS):
    for i, (c, _) in enumerate(regions):
        ax2.scatter(i, j, s=40, color=PAL[t] if t in c else "#ddd", zorder=3)
    ax2.axhline(j, color="#eee", zorder=0)
ax2.set_yticks(range(3)); ax2.set_yticklabels(N.TOOLS); ax2.set_xticks([]); ax2.grid(False)
fig.tight_layout(); fig.savefig(F / "fig2_upset_overlap.pdf", bbox_inches="tight"); fig.savefig(F / "fig2_upset_overlap.png", dpi=200, bbox_inches="tight")

# Fig 3: heatmap of per-image F1 (name+version, all scored ecos)
g = pd.read_csv(R / "metrics_gt.csv")
g = g[(g.level == "name+version") & (g.scope == "all")]
piv = g.pivot_table(index="image", columns="tool", values="f1")[list(PAL)]
fig, ax = plt.subplots(figsize=(4.2, 4.2))
sns.heatmap(piv, annot=True, fmt=".2f", cmap="RdYlGn", vmin=0.5, vmax=1, ax=ax, cbar=False)
ax.set_title("F1 vs ground truth (name+version)"); ax.set_xlabel(""); ax.set_ylabel("")
fig.tight_layout(); fig.savefig(F / "fig3_f1_heatmap.pdf"); fig.savefig(F / "fig3_f1_heatmap.png", dpi=200)
print("figures written:", sorted(p.name for p in F.iterdir()))
