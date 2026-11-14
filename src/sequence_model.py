#!/usr/bin/env python3
"""Step 10 - Sequence model: does temporal context help?

Every other detector scores one 5-minute window in isolation. Here each window is described by the
last L windows of the same entity (default 4 x 5 min = 20 min of history, missing steps = silence),
and a neural autoencoder learns what a *normal sequence* looks like. A window is anomalous when its
whole recent history is hard to reconstruct (e.g. quiet -> burst of failures -> success).

Trained on the EASY dataset without labels, tested on the HARD unseen dataset (labels only for scoring).
Pure scikit-learn (no GPU / PyTorch needed): MLP autoencoder over the flattened sequence.

Usage: python src/sequence_model.py [--length 4]
Outputs: reports/sequence_model.csv  (and prints the comparison next to Isolation Forest)
"""
import argparse
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

STEP = pd.Timedelta("5min")
SEQ_FEATURES = ["n_events", "n_fail", "n_accept", "n_sudo", "n_distinct_users", "n_invalid_user", "external", "offhours"]
COUNTS = ["n_events", "n_fail", "n_accept", "n_sudo", "n_distinct_users", "n_invalid_user"]


def build_sequences(df, length=6):
    """One row per observed window -> flattened (length x features) history of the same entity."""
    d = df.copy()
    d["win"] = pd.to_datetime(d["win"])
    base = d[SEQ_FEATURES].fillna(0).copy()
    base[COUNTS] = np.log1p(base[COUNTS])
    base["entity"], base["win"] = d["entity"].values, d["win"].values
    base = base.set_index(["entity", "win"])
    keys = pd.MultiIndex.from_arrays([d["entity"].values, d["win"].values])
    cols = []
    for k in range(length - 1, -1, -1):                       # oldest ... current window
        prev = pd.MultiIndex.from_arrays([d["entity"].values, (d["win"] - k * STEP).values])
        step = base.reindex(prev).fillna(0.0)                  # missing window = no activity
        step.columns = [f"{c}_t-{k}" for c in SEQ_FEATURES]
        cols.append(step.values)
    return np.hstack(cols), keys


def best_f1(y, s):
    p, r, _ = precision_recall_curve(y, s)
    return (2 * p * r / np.clip(p + r, 1e-9, None)).max()


def evaluate(y, s):
    k = int(y.sum())
    return dict(roc_auc=roc_auc_score(y, s), pr_auc=average_precision_score(y, s), best_f1=best_f1(y, s),
                precision_at_k=y[np.argsort(-s)[:k]].mean())


def sequence_scores(tr, te, length=6, seed=42):
    Xtr, _ = build_sequences(tr, length)
    Xte, _ = build_sequences(te, length)
    sc = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = sc.transform(Xtr), sc.transform(Xte)
    ae = MLPRegressor(hidden_layer_sizes=(64, 16, 64), activation="relu", max_iter=400,
                      early_stopping=True, random_state=seed)
    ae.fit(Xtr_s, Xtr_s)
    return ((ae.predict(Xte_s) - Xte_s) ** 2).mean(axis=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/processed/features.csv")
    ap.add_argument("--test", default="data/hard_processed/features.csv")
    ap.add_argument("--length", type=int, default=4, help="history length in 5-minute windows (4 chosen on a separate validation set, seed 7)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    tr, te = pd.read_csv(a.train), pd.read_csv(a.test)
    y = te["label"].fillna(0).astype(int).values

    rows = []
    s_seq = sequence_scores(tr, te, a.length, a.seed)
    rows.append(dict(model=f"Sequence autoencoder ({a.length}x5min)", **evaluate(y, s_seq)))

    # single-window reference with the same 8 raw features (so the only difference is temporal context)
    Xtr1, _ = build_sequences(tr, 1)
    Xte1, _ = build_sequences(te, 1)
    sc = StandardScaler().fit(Xtr1)
    m = IsolationForest(n_estimators=300, random_state=a.seed).fit(sc.transform(Xtr1))
    rows.append(dict(model="Isolation Forest (single window, same features)", **evaluate(y, -m.score_samples(sc.transform(Xte1)))))

    res = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    res.to_csv("reports/sequence_model.csv", index=False)
    print(f"test: {len(te)} windows, {y.sum()} attacks (hard, unseen)\n")
    print(res.round(3).to_string(index=False))
    print("\nOK -> reports/sequence_model.csv")


if __name__ == "__main__":
    main()
