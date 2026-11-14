#!/usr/bin/env python3
"""Step 3 - Unsupervised anomaly detection (Isolation Forest) on window features.

Labels are NEVER used for training, only to evaluate at the end.
Outputs: models/iforest.joblib, reports/alerts.csv
"""
import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

FEATURES = ["n_events", "n_fail", "n_accept", "n_sudo", "n_sudo_denied", "n_distinct_users",
            "n_invalid_user", "external", "offhours", "root_shell", "fail_ratio", "hour"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="data/processed/features.csv")
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = pd.read_csv(a.features, parse_dates=["win"])
    X = df[FEATURES].fillna(0)

    model = IsolationForest(n_estimators=300, contamination=a.contamination, random_state=a.seed)
    model.fit(X)
    df["anomaly_score"] = -model.score_samples(X)          # higher = more anomalous
    df["pred"] = (model.predict(X) == -1).astype(int)

    Path("models").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, "models/iforest.joblib")

    alerts = df[df["pred"] == 1].sort_values("anomaly_score", ascending=False)
    alerts[["entity", "win", "anomaly_score", "n_fail", "n_distinct_users", "n_sudo_denied",
            "external", "offhours", "attack_type", "label"]].to_csv("reports/alerts.csv", index=False)

    print(f"{len(alerts)} alerts out of {len(df)} windows (contamination={a.contamination})\n")
    print("Confusion matrix [[TN FP] [FN TP]]:\n", confusion_matrix(df["label"], df["pred"]))
    print("\n", classification_report(df["label"], df["pred"], target_names=["normal", "attack"], digits=3))
    print("Top alerts:")
    print(alerts.head(12)[["entity", "win", "anomaly_score", "n_fail", "offhours", "attack_type"]].to_string(index=False))
    missed = df[(df["label"] == 1) & (df["pred"] == 0)]
    if len(missed):
        print("\nMISSED attacks:")
        print(missed[["entity", "win", "anomaly_score", "n_fail", "n_sudo_denied", "attack_type"]].to_string(index=False))


if __name__ == "__main__":
    main()
