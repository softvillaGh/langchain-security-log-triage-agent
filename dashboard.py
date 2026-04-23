import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI Security Triage Dashboard", layout="wide")

st.title("AI Security Triage Dashboard")
st.caption("Consulting-ready triage, enrichment, and reporting view")

report_files = sorted(Path("outputs").glob("*_report_*.json"), reverse=True)

if not report_files:
    st.warning("No report files found in outputs/. Run the triage engine first.")
    st.stop()

selected_file = st.selectbox("Select report", [str(f) for f in report_files])

with open(selected_file, "r") as f:
    report = json.load(f)

summary = report.get("summary", {})
events = report.get("events", [])
df = pd.DataFrame(events)

st.subheader("Executive Summary")
st.info(summary.get("headline", "No headline available."))

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Events", summary.get("total_events", 0))
col2.metric("Critical", summary.get("critical_events", 0))
col3.metric("High", summary.get("high_events", 0))
col4.metric("Low", summary.get("low_events", 0))
col5.metric("Unique IPs", summary.get("unique_ips", 0))

left, right = st.columns([2, 1])

with left:
    st.subheader("Severity Distribution")
    if "severity" in df.columns and not df.empty:
        st.bar_chart(df["severity"].value_counts())

    st.subheader("Attack Types")
    if "attack_type" in df.columns and not df.empty:
        st.bar_chart(df["attack_type"].value_counts())

with right:
    st.subheader("Top Attack Types")
    top_attack_types = summary.get("top_attack_types", {})
    if top_attack_types:
        for attack, count in top_attack_types.items():
            st.write(f"**{attack}** — {count}")
    else:
        st.write("No attack type summary available.")

st.subheader("Filters")

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    severity_options = sorted(df["severity"].dropna().unique().tolist()) if "severity" in df.columns else []
    selected_severity = st.multiselect("Severity", severity_options, default=severity_options)

with filter_col2:
    source_options = sorted(df["source"].dropna().unique().tolist()) if "source" in df.columns else []
    selected_sources = st.multiselect("Source", source_options, default=source_options)

with filter_col3:
    attack_options = sorted(df["attack_type"].dropna().unique().tolist()) if "attack_type" in df.columns else []
    selected_attacks = st.multiselect("Attack Type", attack_options, default=attack_options)

filtered_df = df.copy()

if "severity" in filtered_df.columns and selected_severity:
    filtered_df = filtered_df[filtered_df["severity"].isin(selected_severity)]

if "source" in filtered_df.columns and selected_sources:
    filtered_df = filtered_df[filtered_df["source"].isin(selected_sources)]

if "attack_type" in filtered_df.columns and selected_attacks:
    filtered_df = filtered_df[filtered_df["attack_type"].isin(selected_attacks)]

st.subheader("Filtered Events")
st.dataframe(filtered_df, use_container_width=True)

st.subheader("Critical and High Events")
if "severity" in filtered_df.columns:
    priority_df = filtered_df[filtered_df["severity"].isin(["Critical", "High"])]
    st.dataframe(priority_df, use_container_width=True)

st.subheader("Download")
csv_data = filtered_df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download filtered events as CSV",
    data=csv_data,
    file_name="filtered_events.csv",
    mime="text/csv"
)
