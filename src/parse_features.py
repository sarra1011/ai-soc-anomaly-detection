#!/usr/bin/env python3
"""Step 2 - Parse auth.log -> events table -> per-(entity, time window) features.

Outputs:
  data/processed/events.csv    one row per log line (structured)
  data/processed/features.csv  one row per (entity, 5-min window) + label (from labels.csv, eval only)
"""
import argparse
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

# private ranges + the lab "legitimate" client (127.0.0.1); every other address counts as external
INTERNAL = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.0\.0\.1$)")
LINE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>\w+)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$")
RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port")
RE_INVALID = re.compile(r"Failed password for invalid user")
RE_ACC = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+) port")
RE_SUDO = re.compile(r"^(?P<user>\S+) : (?P<rest>.*)COMMAND=(?P<cmd>.*)$")
RE_ANY_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_SESS = re.compile(r"session (?P<state>opened|closed) for user (?P<user>\S+)")


def parse(path, year):
    return parse_lines(Path(path).read_text().splitlines(), year)


def parse_lines(lines, year, first_line_no=1):
    rows = []
    for i, raw in enumerate(lines, first_line_no):
        m = LINE.match(raw)
        if not m:
            continue
        d = m.groupdict()
        t = datetime.strptime(f"{year} {d['mon']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S")
        r = dict(line_no=i, ts=t, proc=d["proc"], event="other", user=None, ip=None, invalid=0, cmd=None, method=None)
        msg = d["msg"]
        if (x := RE_FAIL.search(msg)):
            r.update(event="ssh_fail", user=x["user"], ip=x["ip"], invalid=int(bool(RE_INVALID.search(msg))))
        elif (x := RE_ACC.search(msg)):
            r.update(event="ssh_accept", user=x["user"], ip=x["ip"], method=x["method"])
        elif d["proc"] == "sudo" and (x := RE_SUDO.match(msg)):
            denied = "NOT in sudoers" in x["rest"]
            r.update(event="sudo_denied" if denied else "sudo_cmd", user=x["user"], cmd=x["cmd"])
        elif (x := RE_SESS.search(msg)):
            r.update(event=f"session_{x['state']}", user=x["user"])
        if r["ip"] is None and r["event"] == "other":      # attribute "Invalid user X from IP", "Connection closed by IP", ...
            m_ip = RE_ANY_IP.search(msg)
            if m_ip:
                r["ip"] = m_ip.group(1)
        rows.append(r)
    return pd.DataFrame(rows)


def build_features(ev, window="5min"):
    ev = ev.copy()
    ev["entity"] = ev["ip"].fillna("user:" + ev["user"].fillna("?"))
    ev["win"] = ev["ts"].dt.floor(window)
    ev["external"] = (~ev["ip"].fillna("10.0.0.1").str.match(INTERNAL)).astype(int)
    ev["offhours"] = ((ev["ts"].dt.hour < 7) | (ev["ts"].dt.hour >= 20)).astype(int)
    ev["root_shell"] = ev["cmd"].fillna("").str.contains(r"/bin/(?:ba)?sh|/etc/shadow").astype(int)

    ev["is_fail"] = (ev["event"] == "ssh_fail").astype(int)
    ev["is_accept"] = (ev["event"] == "ssh_accept").astype(int)
    ev["is_sudo"] = ev["event"].isin(["sudo_cmd", "sudo_denied"]).astype(int)
    ev["is_denied"] = (ev["event"] == "sudo_denied").astype(int)
    g = ev.groupby(["entity", "win"])
    f = pd.DataFrame({
        "n_events": g.size(),
        "n_fail": g["is_fail"].sum(),
        "n_accept": g["is_accept"].sum(),
        "n_sudo": g["is_sudo"].sum(),
        "n_sudo_denied": g["is_denied"].sum(),
        "n_distinct_users": g["user"].nunique(),
        "n_invalid_user": g["invalid"].sum(),
        "external": g["external"].max(),
        "offhours": g["offhours"].max(),
        "root_shell": g["root_shell"].max(),
        "max_line": g["line_no"].max(),
        "min_line": g["line_no"].min(),
    }).reset_index()
    f["fail_ratio"] = f["n_fail"] / (f["n_fail"] + f["n_accept"]).clip(lower=1)
    f["hour"] = f["win"].dt.hour

    # --- Step 6: long-window features per entity (catch slow-and-low) ---
    g2 = f.sort_values("win").set_index("win")
    g2["fail_active"] = (g2["n_fail"] > 0).astype(int)
    for col, w, name in [("n_fail", "1h", "fails_1h"), ("n_fail", "6h", "fails_6h"), ("fail_active", "1h", "active_win_1h")]:
        r = g2.groupby("entity")[col].rolling(w).sum().rename(name).reset_index()
        f = f.merge(r, on=["entity", "win"], how="left")

    # --- Step 6: global feature - distinct IPs failing against root/admin in the last 30 min (catch distributed) ---
    tf = ev[(ev["event"] == "ssh_fail") & ev["user"].isin(["root", "admin"])][["win", "ip"]].drop_duplicates()
    uniq = sorted(f["win"].unique())
    cnt = {}
    for w in uniq:
        m = (tf["win"] > w - pd.Timedelta("30min")) & (tf["win"] <= w)
        cnt[w] = tf.loc[m, "ip"].nunique()
    f["global_ips_30m"] = f["win"].map(cnt).fillna(0).astype(int)
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="data/raw/auth.log")
    ap.add_argument("--labels", default="data/raw/labels.csv")
    ap.add_argument("--out", default="data/processed")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="syslog lines have no year")
    a = ap.parse_args()

    ev = parse(a.log, a.year)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ev.to_csv(out / "events.csv", index=False)

    feats = build_features(ev)
    # evaluation-only label: window is an attack if any of its lines is an attack
    if Path(a.labels).exists():
        lab = pd.read_csv(a.labels)
    else:  # real, unlabeled logs
        lab = pd.DataFrame({"line_no": ev["line_no"], "label": 0, "attack_type": "unlabeled"})
    ev = ev.merge(lab, on="line_no", how="left")
    ev["label"] = ev["label"].fillna(0).astype(int)
    ev["attack_type"] = ev["attack_type"].fillna("normal")
    ev["entity"] = ev["ip"].fillna("user:" + ev["user"].fillna("?"))
    ev["win"] = ev["ts"].dt.floor("5min")
    wl = ev.groupby(["entity", "win"]).agg(label=("label", "max"),
                                           attack_type=("attack_type", lambda s: next((x for x in s if x != "normal"), "normal"))).reset_index()
    feats = feats.merge(wl, on=["entity", "win"], how="left")
    feats.drop(columns=["max_line", "min_line"]).to_csv(out / "features.csv", index=False)

    print(f"events:   {len(ev)} lines parsed -> {out}/events.csv")
    print(f"features: {len(feats)} windows ({int(feats['label'].sum())} attack windows) -> {out}/features.csv")
    print("\nEvent types:\n", ev["event"].value_counts().to_string())
    print("\nAttack windows by type:\n", feats[feats["label"] == 1]["attack_type"].value_counts().to_string())
    print("\nTop 5 windows by n_fail:\n", feats.sort_values("n_fail", ascending=False).head(5)[
        ["entity", "win", "n_fail", "n_distinct_users", "fail_ratio", "label"]].to_string(index=False))


if __name__ == "__main__":
    main()
