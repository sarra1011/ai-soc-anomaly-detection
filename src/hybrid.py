#!/usr/bin/env python3
"""Step 4+6 - Detection rules + ML score -> hybrid alerts -> grouped INCIDENTS.

Needs: features.csv (step 2/6) and models/iforest.joblib (step 3).
Severity: CRITICAL (compromise) > HIGH (rule) > REVIEW (ML-only, no rule matched)
Outputs: --report (window alerts), --report with _incidents suffix (grouped incidents)
"""
import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

SUSPECT = lambda d: (d["external"] == 1) | (d["n_distinct_users"] >= 2) | (d["n_invalid_user"] > 0)  # noqa: E731

RULES = {
    "R1_bruteforce":      (lambda d: (d["n_fail"] >= 10) & SUSPECT(d),                          "HIGH"),
    "R2_password_spray":  (lambda d: (d["n_distinct_users"] >= 4) & (d["n_fail"] >= 5),         "HIGH"),
    "R3_login_after_fails": (lambda d: (d["n_fail"] >= 5) & (d["n_accept"] >= 1) & SUSPECT(d),  "CRITICAL"),
    "R4_offhours_external_login": (lambda d: (d["n_accept"] >= 1) & (d["external"] == 1) & (d["offhours"] == 1), "HIGH"),
    "R5_priv_esc":        (lambda d: (d["n_sudo_denied"] >= 1) | (d["root_shell"] == 1),        "HIGH"),
    "R6_slow_bruteforce": (lambda d: (d["fails_1h"] >= 8) & (d["active_win_1h"] >= 5),          "HIGH"),
    "R7_distributed_bf":  (lambda d: (d["global_ips_30m"] >= 8) & (d["n_fail"] >= 1) & (d["external"] == 1), "HIGH"),
}
RANK = {"CRITICAL": 3, "HIGH": 2, "REVIEW": 1, "": 0}
GAP = pd.Timedelta("30min")


def metrics(name, y, p):
    print(f"{name:<20} precision={precision_score(y, p, zero_division=0):.3f} "
          f"recall={recall_score(y, p):.3f} f1={f1_score(y, p, zero_division=0):.3f} alerts={int(p.sum())}")


def add_incident_ids(d):
    """Group windows of the same source (or the same distributed campaign) closer than 30 min."""
    d = d.sort_values("win").copy()
    d["grp"] = np.where(d["global_ips_30m"] >= 4, "DISTRIBUTED", d["entity"])
    d["_new"] = d.groupby("grp")["win"].diff() > GAP
    d["inc"] = d["grp"] + "#" + d.groupby("grp")["_new"].cumsum().astype(int).astype(str)
    return d


RULE_INFO = {
    "R1_bruteforce": "many failed logins from one source (T1110.001)",
    "R2_password_spray": "many distinct users tried (T1110.003)",
    "R3_login_after_fails": "successful login after repeated failures - probable compromise (T1110, T1078)",
    "R4_offhours_external_login": "off-hours login from an external IP (T1078)",
    "R5_priv_esc": "denied sudo / root shell / shadow access (T1548.003, T1003.008)",
    "R6_slow_bruteforce": "slow-and-low brute force over hours (T1110.001)",
    "R7_distributed_bf": "many IPs failing against root/admin (T1110)",
}


def apply_rules_and_ml(df, bundle, ml_threshold=0.72):
    """Adds anomaly_score, rules and severity columns to a features frame."""
    df = df.copy()
    X = df[bundle["features"]].fillna(0)
    df["anomaly_score"] = -bundle["model"].score_samples(X)
    df["rules"] = ""
    df["severity"] = ""
    for name, (cond, sev) in RULES.items():
        hit = cond(df)
        df.loc[hit, "rules"] = np.where(df.loc[hit, "rules"] == "", name, df.loc[hit, "rules"] + "|" + name)
        up = hit & (df["severity"].map(RANK) < RANK[sev])
        df.loc[up, "severity"] = sev
    ml_only = (df["rules"] == "") & (df["anomaly_score"] >= ml_threshold)
    df.loc[ml_only, "severity"] = "REVIEW"
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="data/processed/features.csv")
    ap.add_argument("--model", default="models/iforest.joblib")
    ap.add_argument("--report", default="reports/hybrid_alerts.csv")
    ap.add_argument("--ml-threshold", type=float, default=0.72, help="ML-only alerts above this score")
    a = ap.parse_args()

    df = pd.read_csv(a.features, parse_dates=["win"])
    bundle = joblib.load(a.model)
    X = df[bundle["features"]].fillna(0)
    df = apply_rules_and_ml(df, bundle, a.ml_threshold)

    df["label"] = df["label"].fillna(0).astype(int)
    y = df["label"]
    labeled = y.sum() > 0
    ml_pred = pd.Series((bundle["model"].predict(X) == -1).astype(int))
    if labeled:
        print("== Window-level evaluation (labels used only here) ==")
        metrics("ML only", y, ml_pred)
        metrics("Rules only", y, (df["rules"] != "").astype(int))
        metrics("Hybrid", y, (df["severity"] != "").astype(int))
    else:
        print("== Unlabeled (real) data: no precision/recall, review the incidents below ==")

    # ---- incidents ----
    al = add_incident_ids(df[df["severity"] != ""])
    al["rank"] = al["severity"].map(RANK)
    inc = al.groupby("inc").agg(severity=("rank", lambda s: {v: k for k, v in RANK.items()}[s.max()]),
                                source=("grp", "first"), start=("win", "min"), end=("win", "max"),
                                windows=("win", "size"), sources=("entity", "nunique"),
                                rules=("rules", lambda s: "|".join(sorted({r for x in s for r in x.split("|") if r}))),
                                true_attack=("label", "max")).reset_index()
    inc["rank"] = inc["severity"].map(RANK)
    inc = inc.sort_values(["rank", "start"], ascending=[False, True]).drop(columns="rank")

    # ground-truth episodes (same grouping logic, from labels) -> incident-level recall
    gt = df[df["label"] == 1].copy()
    gt["grp"] = np.where(gt["attack_type"] == "distributed_bf", "DIST", gt["entity"])
    gt = gt.sort_values("win")
    gt["_new"] = gt.groupby("grp")["win"].diff() > GAP
    gt["ep"] = gt["grp"] + "#" + gt.groupby("grp")["_new"].cumsum().astype(int).astype(str)
    alerted = set(df.loc[df["severity"] != "", "win"].astype(str) + df.loc[df["severity"] != "", "entity"])
    gt["det"] = (gt["win"].astype(str) + gt["entity"]).isin(alerted)
    ep = gt.groupby("ep").agg(det=("det", "max"), kind=("attack_type", "first"))

    if labeled:
        print("\n== Incident-level evaluation ==")
        print(f"Incidents raised: {len(inc)} | real attacks among them: {int(inc['true_attack'].sum())} | "
              f"false incidents: {int((inc['true_attack'] == 0).sum())}")
        print(f"Attack episodes: {len(ep)} | detected: {int(ep['det'].sum())} ({ep['det'].mean():.0%})")
        if (~ep["det"]).any():
            print("Missed episodes:\n", ep[~ep["det"]].to_string())
    else:
        print(f"\nIncidents raised: {len(inc)}")

    inc.to_csv(a.report.replace(".csv", "_incidents.csv"), index=False)
    al.drop(columns=["_new", "rank"]).to_csv(a.report, index=False)
    print("\n== Incidents ==")
    print(inc[["severity", "source", "start", "end", "windows", "sources", "rules", "true_attack"]].to_string(index=False))


if __name__ == "__main__":
    main()
