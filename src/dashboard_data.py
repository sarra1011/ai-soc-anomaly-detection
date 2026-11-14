"""Data layer for the Streamlit dashboard (no UI code, so it can be unit-tested)."""
import json
from pathlib import Path

import pandas as pd

SEV_ORDER = ["CRITICAL", "HIGH", "REVIEW"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
COLUMNS = ["severity", "source", "start", "end", "windows", "sources", "score", "rules", "rule_desc", "action"]


def _empty():
    return pd.DataFrame(columns=COLUMNS)


def load_live_jsonl(path):
    """reports/live_alerts.jsonl -> one row per incident (re-alerts on escalation are merged)."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return _empty()
    rows = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:              # half-written last line while the detector is writing
            continue
        rules = r.get("rules", [])
        rows.append(dict(severity=r["severity"], source=r["source"], start=r["start"], end=r["end"],
                         windows=r.get("windows", 1), sources=r.get("sources", 1), score=r.get("score"),
                         rules=[x["id"] for x in rules], rule_desc=" | ".join(x["desc"] for x in rules),
                         action=r.get("action", "")))
    if not rows:
        return _empty()
    df = pd.DataFrame(rows)
    df["rank"] = df["severity"].map(SEV_RANK)
    # same source + overlapping start => the same incident escalated; keep the most severe, latest record
    df = df.reset_index().sort_values(["source", "start", "rank", "index"], ascending=[True, True, True, False])
    df = df.drop_duplicates(["source", "start"], keep="first").drop(columns=["rank", "index"])
    return _finish(df)


def load_incidents_csv(path):
    """reports/*_incidents.csv produced by src/hybrid.py."""
    p = Path(path)
    if not p.exists():
        return _empty()
    df = pd.read_csv(p)
    df["rules"] = df["rules"].fillna("").apply(lambda s: [x for x in str(s).split("|") if x])
    df["rule_desc"] = ""
    df["action"] = ""
    df["score"] = float("nan")
    return _finish(df)


def _finish(df):
    df = df.copy()
    df["start"], df["end"] = pd.to_datetime(df["start"]), pd.to_datetime(df["end"])
    cols = COLUMNS + [c for c in ("true_attack",) if c in df.columns]
    df = df[cols]
    return df.sort_values("start").reset_index(drop=True)


def kpis(df):
    sev = df["severity"].value_counts() if len(df) else {}
    return dict(total=len(df), critical=int(sev.get("CRITICAL", 0)), high=int(sev.get("HIGH", 0)),
                review=int(sev.get("REVIEW", 0)), sources=int(df["source"].nunique()) if len(df) else 0)


def rule_counts(df):
    if not len(df):
        return pd.DataFrame(columns=["rule", "incidents"])
    ex = df.explode("rules").dropna(subset=["rules"])
    ex = ex[ex["rules"] != ""]
    return ex.groupby("rules").size().rename("incidents").reset_index().rename(columns={"rules": "rule"}) \
             .sort_values("incidents", ascending=False)


def apply_filters(df, severities, rules, source_query):
    out = df[df["severity"].isin(severities)]
    if rules:
        out = out[out["rules"].apply(lambda rs: any(r in rules for r in rs))]
    if source_query:
        out = out[out["source"].str.contains(source_query.strip(), case=False, regex=False)]
    return out
