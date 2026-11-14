#!/usr/bin/env python3
"""Step 7 - SOC dashboard (one PNG, 4 panels) from events + incidents.

Panels: 1) incident timeline  2) failed logins per hour + incident bands
        3) top sources by failed logins  4) incidents by rule
Usage:  python3 src/report.py --events data/hard_processed/events.csv \
            --incidents reports/hard_alerts_incidents.csv --out reports/soc_dashboard.png
"""
import argparse

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.dates as mdates  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

SEV_COLOR = {"CRITICAL": "#B3261E", "HIGH": "#E8710A", "REVIEW": "#7A8CA5"}   # status colors, always labelled
INK, MUTED, GRID, BAR = "#1F2937", "#6B7280", "#E5E7EB", "#3B6FB6"


def style(ax, title):
    ax.set_title(title, loc="left", fontsize=11, color=INK, fontweight="bold", pad=10)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=8, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/hard_processed/events.csv")
    ap.add_argument("--incidents", default="reports/hard_alerts_incidents.csv")
    ap.add_argument("--out", default="reports/soc_dashboard.png")
    a = ap.parse_args()

    ev = pd.read_csv(a.events, parse_dates=["ts"])
    inc = pd.read_csv(a.incidents, parse_dates=["start", "end"])
    end_pad = pd.Timedelta("5min")
    tfmt = "%H:%M" if (ev["ts"].max() - ev["ts"].min()) < pd.Timedelta("2D") else "%d %b"

    fig, ax = plt.subplots(2, 2, figsize=(15, 9), facecolor="white")
    fig.suptitle("SOC anomaly detection - dashboard", x=0.01, y=0.985, ha="left", fontsize=15, color=INK, fontweight="bold")
    n_sev = inc["severity"].value_counts()
    fig.text(0.01, 0.925, "  ".join(f"{k}: {n_sev.get(k, 0)}" for k in ("CRITICAL", "HIGH", "REVIEW"))
             + f"   |   {len(inc)} incidents from {len(ev)} log lines", color=MUTED, fontsize=10)

    # 1) incident timeline: one row per attack type, marker = incident, color = severity
    def kind(rules):
        r = rules if isinstance(rules, str) else ""
        for key, name in (("R7", "Distributed brute force"), ("R6", "Slow brute force"), ("R3", "Brute force"),
                          ("R1", "Brute force"), ("R2", "Brute force"), ("R4", "Off-hours external login"),
                          ("R5", "Privilege escalation")):
            if key in r:
                return name
        return "ML-only anomaly"
    inc["kind"] = inc["rules"].map(kind)
    order = ["Brute force", "Slow brute force", "Distributed brute force", "Off-hours external login",
             "Privilege escalation", "ML-only anomaly"]
    a1 = ax[0, 0]
    for r in inc.itertuples():
        y = order.index(r.kind)
        a1.plot([r.start, r.end + end_pad], [y, y], color=SEV_COLOR[r.severity], linewidth=7, solid_capstyle="round", alpha=0.9)
        a1.scatter([r.start], [y], s=70, color=SEV_COLOR[r.severity], edgecolor="white", linewidth=1.5, zorder=3)
    cnt = inc["kind"].value_counts()
    a1.set_yticks(range(len(order)))
    a1.set_yticklabels([f"{k} ({cnt.get(k, 0)})" for k in order], fontsize=8.5)
    a1.invert_yaxis()
    a1.xaxis.set_major_formatter(mdates.DateFormatter(tfmt))
    style(a1, "Incident timeline (count per type)")
    a1.grid(axis="x", color=GRID, linewidth=0.7)
    a1.grid(axis="y", visible=False)
    fig.legend(handles=[Line2D([0], [0], marker="o", color="w", markerfacecolor=c, markersize=10, label=k)
                        for k, c in SEV_COLOR.items()], fontsize=10, frameon=False, loc="upper right",
               bbox_to_anchor=(0.99, 0.985), ncol=3, title="Severity", title_fontsize=9)

    # 2) failed logins per hour, incident starts marked on top
    a2 = ax[0, 1]
    f = ev[ev["event"] == "ssh_fail"].set_index("ts").resample("1h").size()
    a2.fill_between(f.index, f.values, color=BAR, alpha=0.25, linewidth=0)
    a2.plot(f.index, f.values, color=BAR, linewidth=1.5)
    top_y = f.max() * 1.12
    a2.set_ylim(0, f.max() * 1.22)
    for sev in ("REVIEW", "HIGH", "CRITICAL"):
        d = inc[inc["severity"] == sev]
        a2.scatter(d["start"], [top_y] * len(d), marker="v", s=55, color=SEV_COLOR[sev], edgecolor="white", linewidth=0.8, zorder=3)
    a2.xaxis.set_major_formatter(mdates.DateFormatter(tfmt))
    style(a2, "Failed SSH logins per hour (triangle = incident start)")

    # 3) top sources by failed logins
    a3 = ax[1, 0]
    top = ev[ev["event"] == "ssh_fail"].groupby("ip").size().sort_values(ascending=False).head(8)[::-1]
    a3.barh(top.index, top.values, color=BAR, height=0.6)
    for y, v in enumerate(top.values):
        a3.text(v, y, f" {v}", va="center", fontsize=8, color=INK)
    style(a3, "Top 8 sources by failed logins")
    a3.grid(axis="y", visible=False)
    a3.grid(axis="x", color=GRID, linewidth=0.7)

    # 4) incidents by rule
    a4 = ax[1, 1]
    rules = inc["rules"].fillna("").str.split("|").explode()
    rules = rules[rules != ""].value_counts()[::-1]
    if rules.empty:
        rules = pd.Series({"(ML only)": len(inc)})
    a4.barh(rules.index, rules.values, color=BAR, height=0.6)
    for y, v in enumerate(rules.values):
        a4.text(v, y, f" {v}", va="center", fontsize=8, color=INK)
    style(a4, "Incidents by detection rule")
    a4.grid(axis="y", visible=False)
    a4.grid(axis="x", color=GRID, linewidth=0.7)
    ml = int((inc["rules"].fillna("") == "").sum())
    a4.text(0.99, 0.02, f"ML-only (REVIEW) incidents: {ml}", transform=a4.transAxes, ha="right", fontsize=8, color=MUTED)

    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(a.out, dpi=130)
    print(f"OK -> {a.out}")


if __name__ == "__main__":
    main()
