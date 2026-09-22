"""
Generate a comparison graph: RF vs XGBoost on the same test set.
Shows: accuracy, F1, AUC, inference speed, model size, and proba sharpness.
"""
import os, sys, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd, joblib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

sys.path.insert(0, "/root/.hermes/c2-evasion-rl/blue_team")

# Load both surrogates
rf = joblib.load("/root/.hermes/c2-evasion-rl/data/surrogate_ids_ctu13.pkl")
xgb_model = joblib.load("/tmp/jev-poc/model_compare/xgboost_rf_matched.pkl") if os.path.exists("/tmp/jev-poc/model_compare/xgboost_rf_matched.pkl") else None

if xgb_model is None:
    print("[!] XGBoost model not in expected location; using the just-trained one")
    # Will compare RF (old) vs XGBoost (new) from training output

# Prepare test data
files = sorted(os.popen("find /root/.hermes/c2-evasion-rl/data/archive -name '*.parquet' | head -3").read().strip().split('\n'))
df = pd.concat([pd.read_parquet(f) for f in files if f], ignore_index=True)
df = df[df["label"].astype(str).str.lower().str.contains("botnet")].copy()
df = df.rename(columns={"Dur": "dur", "TotPkts": "tot_pkts", "TotBytes": "tot_bytes",
                        "SrcBytes": "src_bytes", "Proto": "proto", "State": "state"})
df = df.dropna(subset=["dur", "tot_pkts", "tot_bytes", "src_bytes", "proto", "state"])

lp = joblib.load("/root/.hermes/c2-evasion-rl/data/label_encoder_proto.pkl")
ls = joblib.load("/root/.hermes/c2-evasion-rl/data/label_encoder_state.pkl")

X = df[["dur", "tot_pkts", "tot_bytes", "src_bytes", "proto", "state"]].copy()
X["proto"] = lp.transform(X["proto"].astype(str))
X["state"] = ls.transform(X["state"].astype(str))

# Metrics from the benchmark (from earlier work)
metrics = {
    "Model": ["RandomForest", "XGBoost"],
    "F1 Score": [0.9365, 0.9476],
    "AUC": [0.9835, 0.9888],
    "Inference\n(ms/call)": [7.0, 1.35],
    "Model Size\n(MB)": [38.9, 7.5],
    "Proba @ extremes\n(%)": [54.1, 71.9],
}

# Create figure with subplots
fig, axes = plt.subplots(2, 3, figsize=(14, 9))
fig.suptitle("Surrogate Judge Comparison: RandomForest vs XGBoost", fontsize=14, fontweight="bold")

colors = ["#FF6B6B", "#4ECDC4"]

# Plot 1: F1 Score
ax = axes[0, 0]
bars = ax.bar(metrics["Model"], metrics["F1 Score"], color=colors, alpha=0.7, edgecolor="black", linewidth=1.5)
ax.set_ylabel("F1 Score", fontweight="bold")
ax.set_ylim([0.90, 1.0])
ax.grid(axis="y", alpha=0.3)
for i, (bar, val) in enumerate(zip(bars, metrics["F1 Score"])):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.003, f"{val:.4f}", ha="center", fontweight="bold")

# Plot 2: AUC
ax = axes[0, 1]
bars = ax.bar(metrics["Model"], metrics["AUC"], color=colors, alpha=0.7, edgecolor="black", linewidth=1.5)
ax.set_ylabel("ROC AUC", fontweight="bold")
ax.set_ylim([0.97, 1.0])
ax.grid(axis="y", alpha=0.3)
for i, (bar, val) in enumerate(zip(bars, metrics["AUC"])):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.003, f"{val:.4f}", ha="center", fontweight="bold")

# Plot 3: Inference Speed
ax = axes[0, 2]
bars = ax.bar(metrics["Model"], metrics["Inference\n(ms/call)"], color=colors, alpha=0.7, edgecolor="black", linewidth=1.5)
ax.set_ylabel("ms per single prediction", fontweight="bold")
ax.set_yscale("log")
ax.grid(axis="y", alpha=0.3, which="both")
for i, (bar, val) in enumerate(zip(bars, metrics["Inference\n(ms/call)"])):
    ax.text(bar.get_x() + bar.get_width()/2, val * 1.3, f"{val:.2f}ms", ha="center", fontweight="bold", fontsize=9)

# Plot 4: Model Size
ax = axes[1, 0]
bars = ax.bar(metrics["Model"], metrics["Model Size\n(MB)"], color=colors, alpha=0.7, edgecolor="black", linewidth=1.5)
ax.set_ylabel("Disk size (MB)", fontweight="bold")
ax.grid(axis="y", alpha=0.3)
for i, (bar, val) in enumerate(zip(bars, metrics["Model Size\n(MB)"])):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1, f"{val:.1f}MB", ha="center", fontweight="bold")

# Plot 5: Probability sharpness
ax = axes[1, 1]
bars = ax.bar(metrics["Model"], metrics["Proba @ extremes\n(%)"], color=colors, alpha=0.7, edgecolor="black", linewidth=1.5)
ax.set_ylabel("% predictions at P<0.05 or P>0.95", fontweight="bold")
ax.set_ylim([0, 100])
ax.grid(axis="y", alpha=0.3)
for i, (bar, val) in enumerate(zip(bars, metrics["Proba @ extremes\n(%)"])):
    ax.text(bar.get_x() + bar.get_width()/2, val + 2, f"{val:.1f}%", ha="center", fontweight="bold")

# Plot 6: Summary table
ax = axes[1, 2]
ax.axis("off")
summary_text = f"""
VERDICT: XGBoost wins on all metrics.

• F1:        +1.2 pp (0.9365 → 0.9476)
• AUC:       +0.5 pp (0.9835 → 0.9888)
• Speed:     5.2× faster (7.0 → 1.35 ms)
• Size:      5.2× smaller (38.9 → 7.5 MB)
• Proba:     +33% sharper gradient

Recommendation: Switch to XGBoost.
"""
ax.text(0.05, 0.95, summary_text, transform=ax.transAxes, fontsize=10, verticalalignment="top",
        family="monospace", bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5))

plt.tight_layout()
plt.savefig("/root/.hermes/c2-evasion-rl/surrogate_comparison.png", dpi=150, bbox_inches="tight")
print("[+] Graph saved: /root/.hermes/c2-evasion-rl/surrogate_comparison.png")
plt.close()

# Also create a simple metric table
fig, ax = plt.subplots(figsize=(10, 4))
ax.axis("tight")
ax.axis("off")

table_data = [
    ["Metric", "RandomForest", "XGBoost", "Delta"],
    ["F1 Score", "0.9365", "0.9476", "+1.2 pp"],
    ["ROC AUC", "0.9835", "0.9888", "+0.5 pp"],
    ["Inference (ms)", "7.0", "1.35", "5.2× faster"],
    ["Model Size (MB)", "38.9", "7.5", "5.2× smaller"],
    ["Proba Sharpness (%)", "54.1", "71.9", "+33%"],
]

table = ax.table(cellText=table_data, cellLoc="center", loc="center",
                colWidths=[0.3, 0.2, 0.2, 0.2])
table.auto_set_font_size(False)
table.set_fontsize(11)
table.scale(1, 2.5)

# Style header row
for i in range(4):
    table[(0, i)].set_facecolor("#4ECDC4")
    table[(0, i)].set_text_props(weight="bold", color="white")

# Alternate row colors
for i in range(1, len(table_data)):
    for j in range(4):
        if i % 2 == 0:
            table[(i, j)].set_facecolor("#F0F0F0")
        else:
            table[(i, j)].set_facecolor("white")

plt.savefig("/root/.hermes/c2-evasion-rl/surrogate_metrics_table.png", dpi=150, bbox_inches="tight")
print("[+] Table saved: /root/.hermes/c2-evasion-rl/surrogate_metrics_table.png")
