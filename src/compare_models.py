#!/usr/bin/env python3
"""Step 9 - Compare unsupervised anomaly detectors.

Train on the EASY dataset (no labels), test on the HARD dataset (stealth attacks + benign look-alikes,
unseen seed). Metrics use the labels only for scoring: ROC-AUC, PR-AUC (average precision), best F1,
precision@k (k = number of true attack windows).

Models: Isolation Forest, Local Outlier Factor, One-Class SVM, Autoencoder (MLP), robust z-score baseline.
Outputs: reports/model_comparison.csv, reports/model_comparison.png
"""
import argparse
import warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve  # noqa: E402
from sklearn.neighbors import LocalOutlierFactor  # noqa: E402
from sklearn.neural_network import MLPRegressor  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.svm import OneClassSVM  # noqa: E402

warnings.filterwarnings("ignore")

FEATURES = ["n_events", "n_fail", "n_accept", "n_sudo", "n_sudo_denied", "n_distinct_users", "n_invalid_user",
            "external", "offhours", "root_shell", "fail_ratio", "hour",
            "fails_1h", "fails_6h", "active_win_1h", "global_ips_30m"]
COUNTS = ["n_events", "n_fail", "n_accept", "n_sudo", "n_sudo_denied", "n_distinct_users", "n_invalid_user",
          "fails_1h", "fails_6h", "active_win_1h", "global_ips_30m"]


def prep(df):
    X = df[FEATURES].fillna(0).copy()
    X[COUNTS] = np.log1p(X[COUNTS])          # heavy-tailed counts -> log scale
    return X.values


def score_models(Xtr, Xte, seed):
    sc = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = sc.transform(Xtr), sc.transform(Xte)
    out = {}

    m = IsolationForest(n_estimators=300, random_state=seed).fit(Xtr_s)
    out["Isolation Forest"] = -m.score_samples(Xte_s)

    m = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(Xtr_s)
    out["Local Outlier Factor"] = -m.score_samples(Xte_s)

    m = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(Xtr_s)
    out["One-Class SVM"] = -m.score_samples(Xte_s)

    ae = MLPRegressor(hidden_layer_sizes=(12, 4, 12), activation="relu", max_iter=600, random_state=seed)
    ae.fit(Xtr_s, Xtr_s)
    out["Autoencoder (MLP)"] = ((ae.predict(Xte_s) - Xte_s) ** 2).mean(axis=1)

    med, mad = np.median(Xtr_s, axis=0), np.median(np.abs(Xtr_s - np.median(Xtr_s, axis=0)), axis=0) + 1e-6
    out["Robust z-score (baseline)"] = np.abs((Xte_s - med) / mad).max(axis=1)
    return out


def best_f1(y, s):
    p, r, _ = precision_recall_curve(y, s)
    f = 2 * p * r / np.clip(p + r, 1e-9, None)
    return f.max()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/processed/features.csv")
    ap.add_argument("--test", default="data/hard_processed/features.csv")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    tr, te = pd.read_csv(a.train), pd.read_csv(a.test)
    y = te["label"].fillna(0).astype(int).values
    scores = score_models(prep(tr), prep(te), a.seed)

    rows = []
    for name, s in scores.items():
        k = int(y.sum())
        topk = y[np.argsort(-s)[:k]].mean()
        rows.append(dict(model=name, roc_auc=roc_auc_score(y, s), pr_auc=average_precision_score(y, s),
                         best_f1=best_f1(y, s), precision_at_k=topk))
    res = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    res.to_csv("reports/model_comparison.csv", index=False)
    print(f"train: {len(tr)} windows (easy) | test: {len(te)} windows, {y.sum()} attacks ({y.mean():.1%}) (hard, unseen)\n")
    print(res.round(3).to_string(index=False))

    fig, ax = plt.subplots(1, 2, figsize=(17, 5), facecolor="white")
    colors = ["#3B6FB6", "#E8710A", "#2E8B57", "#8E5BA8", "#7A8CA5"]
    for (name, s), c in zip(scores.items(), colors):
        fpr, tpr, _ = roc_curve(y, s)
        p, r, _ = precision_recall_curve(y, s)
        ax[0].plot(fpr, tpr, color=c, lw=1.8, label=f"{name} ({roc_auc_score(y, s):.2f})")
        ax[1].plot(r, p, color=c, lw=1.8, label=f"{name} ({average_precision_score(y, s):.2f})")
    ax[0].plot([0, 1], [0, 1], color="#D1D5DB", lw=1, ls="--")
    for axx, t, xl, yl in ((ax[0], "ROC curve (AUC)", "False positive rate", "True positive rate"),
                           (ax[1], "Precision-recall curve (AP)", "Recall", "Precision")):
        axx.set_title(t, loc="left", fontsize=11, fontweight="bold", color="#1F2937")
        axx.set_xlabel(xl, color="#6B7280")
        axx.set_ylabel(yl, color="#6B7280")
        axx.grid(color="#E5E7EB", lw=0.7)
        for sp in ("top", "right"):
            axx.spines[sp].set_visible(False)
        axx.legend(fontsize=8, frameon=False, loc="upper left", bbox_to_anchor=(1.01, 1.0), title="model (score)", title_fontsize=8)
    fig.suptitle("Unsupervised detectors trained on easy data, tested on hard unseen data", x=0.01, ha="left",
                 fontsize=12, color="#1F2937")
    fig.tight_layout()
    fig.savefig("reports/model_comparison.png", dpi=130)
    print("\nOK -> reports/model_comparison.csv, reports/model_comparison.png")


if __name__ == "__main__":
    main()
