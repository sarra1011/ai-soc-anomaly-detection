#!/usr/bin/env python3
"""Live mode - follow a log file, score it continuously and raise incidents as they happen.

  python3 src/live.py --log /var/log/auth.log --follow              # real time (needs read access to the log)
  python3 src/live.py --log data/hard/auth.log --replay             # replay an existing log instantly
  python3 src/live.py --log lab_data/auth.log --follow --enforce    # really block CRITICAL sources (public IPs only)

Needs models/iforest.joblib (python3 src/detect.py). Without it, only the rules run.
Alerts: console + reports/live_alerts.jsonl always; Telegram / e-mail via environment variables (see alerting.py).
CRITICAL incidents trigger the blocker (dry-run unless --enforce).
"""
import argparse
import time
from collections import deque
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import alerting
import hybrid
import parse_features as pf

KEEP = pd.Timedelta("6h")
GAP = pd.Timedelta("30min")
WINDOW = pd.Timedelta("5min")


class LiveDetector:
    def __init__(self, bundle, notifier, blocker, year, ml_threshold=0.72, step_min=5):
        self.bundle, self.notifier, self.blocker = bundle, notifier, blocker
        self.year, self.ml_threshold = year, ml_threshold
        self.step = pd.Timedelta(minutes=step_min)   # how often (in log time) the scoring runs
        self.rows = deque()                # parsed events of the last 6 h
        self.line_no = 0
        self.reported = {}                 # source -> list of {start, end, rank}
        self.last_eval_window = None
        self.n_alerts = 0

    def feed(self, raw):
        self.line_no += 1
        ev = pf.parse_lines([raw], self.year, self.line_no)
        if ev.empty:
            return
        row = ev.iloc[0].to_dict()
        self.rows.append(row)
        while self.rows and self.rows[0]["ts"] < row["ts"] - KEEP:
            self.rows.popleft()
        win = row["ts"].floor(self.step)
        if self.last_eval_window is None:
            self.last_eval_window = win
        elif win > self.last_eval_window:   # a 5-minute window just closed -> evaluate
            self.evaluate()
            self.last_eval_window = win

    def evaluate(self):
        if not self.rows:
            return
        ev = pd.DataFrame(list(self.rows))
        feats = pf.build_features(ev)
        feats["label"] = 0
        if self.bundle is not None:
            df = hybrid.apply_rules_and_ml(feats, self.bundle, self.ml_threshold)
        else:
            df = feats.copy()
            df["rules"], df["severity"], df["anomaly_score"] = "", "", 0.0
            for name, (cond, sev) in hybrid.RULES.items():
                hit = cond(df)
                df.loc[hit, "rules"] = np.where(df.loc[hit, "rules"] == "", name, df.loc[hit, "rules"] + "|" + name)
                up = hit & (df["severity"].map(hybrid.RANK) < hybrid.RANK[sev])
                df.loc[up, "severity"] = sev
        al = df[df["severity"] != ""]
        if al.empty:
            return
        al = hybrid.add_incident_ids(al)
        al["rank"] = al["severity"].map(hybrid.RANK)
        for _, g in al.groupby("inc"):
            self._handle(g)

    def _handle(self, g):
        src = g["grp"].iloc[0]
        rank = int(g["rank"].max())
        start, end = g["win"].min(), g["win"].max()
        seen = self.reported.setdefault(src, [])
        for r in seen:                       # same incident (overlaps or within 30 min)?
            if start <= r["end"] + GAP and end >= r["start"] - GAP:
                r["start"], r["end"] = min(r["start"], start), max(r["end"], end)
                if rank <= r["rank"]:
                    return                   # already reported at this severity or higher
                r["rank"] = rank
                break
        else:
            seen.append(dict(start=start, end=end, rank=rank))
        sev = {v: k for k, v in hybrid.RANK.items()}[rank]
        rules = sorted({x for s in g["rules"] for x in s.split("|") if x})
        inc = dict(severity=sev, source=src, start=str(start), end=str(end), windows=len(g),
                   sources=int(g["entity"].nunique()), score=round(float(g["anomaly_score"].max()), 3),
                   rules=[dict(id=r, desc=hybrid.RULE_INFO.get(r, "")) for r in rules])
        if sev == "CRITICAL" and src != "DISTRIBUTED":
            inc["action"] = self.blocker.block(src)
        self.n_alerts += 1
        self.notifier.send(inc)

    def finish(self):
        self.evaluate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/log/auth.log")
    ap.add_argument("--model", default="models/iforest.joblib")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--follow", action="store_true", help="read the existing content, then keep following new lines")
    mode.add_argument("--replay", action="store_true", help="process the whole file once and exit (default)")
    ap.add_argument("--tail", action="store_true", help="with --follow: skip the existing content, only new lines")
    ap.add_argument("--year", type=int, default=datetime.now().year)
    ap.add_argument("--enforce", action="store_true", help="really run iptables for CRITICAL public IPs (default: dry-run)")
    ap.add_argument("--allow", nargs="*", default=[], help="IPs that must never be blocked")
    ap.add_argument("--min-notify", default="HIGH", choices=["REVIEW", "HIGH", "CRITICAL"])
    ap.add_argument("--ml-threshold", type=float, default=0.72)
    ap.add_argument("--step-min", type=int, default=5, help="score every N minutes of log time (use 30+ to replay faster)")
    a = ap.parse_args()

    bundle = joblib.load(a.model) if Path(a.model).exists() else None
    if bundle is None:
        print("(no model found - rules only; run python3 src/detect.py for the ML part)")
    notifier = alerting.Notifier(min_notify=a.min_notify)
    blocker = alerting.Blocker(enforce=a.enforce, allowlist=a.allow)
    det = LiveDetector(bundle, notifier, blocker, a.year, a.ml_threshold, a.step_min)
    print(f"live detector on {a.log} | channels: {', '.join(notifier.channels)} | "
          f"blocking: {'ENFORCED' if a.enforce else 'dry-run'}\n", flush=True)

    with open(a.log, errors="replace") as f:
        if a.follow and a.tail:
            f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if line:
                    det.feed(line.rstrip("\n"))
                elif a.follow:
                    det.evaluate()           # idle: re-check so slow attacks are not missed
                    time.sleep(2)
                else:
                    break
        except KeyboardInterrupt:
            print("\nstopped")
    det.finish()
    print(f"done - {det.line_no} lines, {det.n_alerts} alerts")


if __name__ == "__main__":
    main()
