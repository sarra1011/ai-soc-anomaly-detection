#!/usr/bin/env python3
"""Step 11 - Live SOC dashboard (Streamlit).

    streamlit run src/dashboard.py

Reads the incidents produced by the pipeline (reports/*_incidents.csv) or the live detector
(reports/live_alerts.jsonl). With the live source selected the page refreshes itself, so you can run
`bash lab/run_live_demo.sh` in one terminal and watch incidents appear here as they are raised.
"""
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dashboard_data import SEV_ORDER, apply_filters, kpis, load_incidents_csv, load_live_jsonl, rule_counts  # noqa: E402

REPORTS = Path(__file__).resolve().parent.parent / "reports"
SEV_COLORS = ["#B42318", "#E8710A", "#7A8CA5"]          # CRITICAL, HIGH, REVIEW (distinct in lightness too)
LIVE = "Live alerts (live_alerts.jsonl)"
# `use_container_width` was replaced by `width="stretch"` in recent Streamlit releases
FULL = {"width": "stretch"} if tuple(int(x) for x in st.__version__.split(".")[:2]) >= (1, 50) else {"use_container_width": True}

st.set_page_config(page_title="AI SOC dashboard", page_icon="🛡️", layout="wide")


def source_options():
    opts = {LIVE: REPORTS / "live_alerts.jsonl"}
    for f in sorted(REPORTS.glob("*_incidents.csv")):
        opts[f"Batch: {f.stem.replace('_incidents', '')}"] = f
    return opts


def load(name, path):
    return load_live_jsonl(path) if name == LIVE else load_incidents_csv(path)


def sev_scale():
    return alt.Scale(domain=SEV_ORDER, range=SEV_COLORS)


def draw(df_all, f_sev, f_rules, f_src):
    df = apply_filters(df_all, f_sev, f_rules, f_src)
    k = kpis(df)
    c = st.columns(5)
    c[0].metric("Incidents", k["total"])
    c[1].metric("🔴 Critical", k["critical"])
    c[2].metric("🟠 High", k["high"])
    c[3].metric("⚪ Review", k["review"])
    c[4].metric("Distinct sources", k["sources"])

    if df.empty:
        st.info("No incidents yet. Start the live demo (`bash lab/run_live_demo.sh`) or pick a batch source in the sidebar.")
        return

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Incident timeline")
        plot = df.assign(end2=df["end"].where(df["end"] > df["start"], df["start"]))
        order = alt.EncodingSortField("start", op="min")
        base = alt.Chart(plot).encode(
            y=alt.Y("source:N", title=None, sort=order, axis=alt.Axis(labelOverlap=False, labelLimit=160)),
            color=alt.Color("severity:N", scale=sev_scale(), legend=alt.Legend(title="Severity", orient="top")),
            tooltip=["severity", "source", "start", "end", "windows", alt.Tooltip("rules:N", title="rules")])
        span = base.mark_rule(size=6).encode(x=alt.X("start:T", title=None), x2="end2:T")     # duration of the incident
        dot = base.mark_circle(size=110, opacity=1).encode(x=alt.X("start:T", title=None))   # where it starts
        st.altair_chart((span + dot).properties(height=max(300, 42 * df["source"].nunique())), **FULL)
    with right:
        st.subheader("Incidents by rule")
        rc = rule_counts(df)
        if rc.empty:
            st.caption("No rule matched: only ML anomaly scores.")
        else:
            st.altair_chart(alt.Chart(rc).mark_bar(color="#3B6FB6", cornerRadiusEnd=3).encode(
                x=alt.X("incidents:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
                y=alt.Y("rule:N", title=None, sort="-x", axis=alt.Axis(labelLimit=220, labelOverlap=False)),
                tooltip=["rule", "incidents"]).properties(height=max(140, 30 * len(rc))), **FULL)

    a, b = st.columns(2)
    with a:
        st.subheader("Incidents per hour")
        per_h = df.assign(hour=df["start"].dt.floor("h")).groupby(["hour", "severity"]).size().rename("n").reset_index()
        st.altair_chart(alt.Chart(per_h).mark_bar(cornerRadiusEnd=2, size=18).encode(
            x=alt.X("hour:T", title=None), y=alt.Y("n:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("severity:N", scale=sev_scale(), legend=None), tooltip=["hour", "severity", "n"]
        ).properties(height=200), **FULL)
    with b:
        st.subheader("Top sources")
        top = df.groupby("source").size().rename("incidents").reset_index().nlargest(8, "incidents")
        st.altair_chart(alt.Chart(top).mark_bar(color="#3B6FB6", cornerRadiusEnd=3).encode(
            x=alt.X("incidents:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
            y=alt.Y("source:N", title=None, sort="-x", axis=alt.Axis(labelOverlap=False)),
            tooltip=["source", "incidents"]).properties(height=max(200, 26 * len(top))), **FULL)

    st.subheader("Incidents")
    show = df.sort_values("start", ascending=False).copy()
    show["rules"] = show["rules"].apply(", ".join)
    cols = [c for c in ("severity", "source", "start", "end", "windows", "rules", "rule_desc", "action", "true_attack")
            if c in show.columns and show[c].astype(str).str.len().gt(0).any()]
    st.dataframe(show[cols], **FULL, hide_index=True)


def main():
    st.title("🛡️ AI-Based SOC Anomaly Detection")
    opts = source_options()
    with st.sidebar:
        st.header("Data")
        name = st.selectbox("Source", list(opts), index=0)
        live = name == LIVE
        refresh = st.slider("Auto-refresh (seconds)", 1, 30, 3, disabled=not live)
        df_all = load(name, opts[name])
        st.header("Filters")
        f_sev = st.multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
        all_rules = sorted({r for rs in df_all["rules"] for r in rs})
        f_rules = st.multiselect("Rule", all_rules)
        f_src = st.text_input("Source contains")
        st.caption(f"File: {opts[name].name}")

    if live:
        @st.fragment(run_every=refresh)
        def live_view():
            draw(load(name, opts[name]), f_sev, f_rules, f_src)
        live_view()
    else:
        draw(df_all, f_sev, f_rules, f_src)


main()
