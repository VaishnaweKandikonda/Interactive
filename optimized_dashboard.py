
"""
📌 Academic Integrity Note:
This dashboard was developed by the student for IS41570 Assignment 2.
Some ideas and structural elements (e.g., Streamlit layout, Plotly usage) were adapted from lecture examples and official documentation.
All final code was written and tested independently by the student.

Referenced sources:
- Streamlit docs: https://docs.streamlit.io/
- Plotly Express examples: https://plotly.com/python/plotly-express/
- NVD CVE format: https://nvd.nist.gov/developers/vulnerabilities
- MITRE ATT&CK JSON structure: https://github.com/mitre/cti
"""

import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Cyber Threat Intelligence Dashboard", layout="wide")
st.title("🛡️ Cyber Threat Intelligence Dashboard")

@st.cache_data
def load_data():
    df = pd.read_csv("CVE_MITRE_Mappings.csv")
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
    df['year'] = df['published_date'].dt.year
    df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
    return df

df = load_data()

# Sidebar filters
st.sidebar.header("🔍 Filters")
selected_years = st.sidebar.multiselect("Select Years", options=sorted(df['year'].dropna().unique()), default=sorted(df['year'].dropna().unique()))
selected_severity = st.sidebar.multiselect("Select Severities", options=df['severity'].dropna().unique(), default=list(df['severity'].dropna().unique()))
selected_tactic = st.sidebar.selectbox("Select MITRE Tactic", options=["All"] + sorted(df["mitre_tactic"].dropna().unique()))
cvss_range = st.sidebar.slider("CVSS Score Range", float(df["cvss_score"].min()), float(df["cvss_score"].max()), (float(df["cvss_score"].min()), float(df["cvss_score"].max())))

# Filter data
filtered_df = df[
    df['year'].isin(selected_years) &
    df['severity'].isin(selected_severity) &
    df['cvss_score'].between(*cvss_range)
]
if selected_tactic != "All":
    filtered_df = filtered_df[filtered_df["mitre_tactic"] == selected_tactic]

# Summary
st.subheader("📊 Summary Metrics")
col1, col2, col3 = st.columns(3)
col1.metric("Total CVEs", len(filtered_df))
col2.metric("Average CVSS", round(filtered_df["cvss_score"].dropna().mean(), 2))
col3.metric("Top CWE", filtered_df["cwe_id"].value_counts().idxmax() if not filtered_df.empty else "N/A")

# Visuals
tab1, tab2, tab3, tab4 = st.tabs(["📉 Severity", "📌 CVSS vs CWE", "📈 Timeline", "🌐 MITRE Mapping"])

with tab1:
    st.plotly_chart(px.histogram(filtered_df, x="severity", color="severity", title="CVEs by Severity"), use_container_width=True)

with tab2:
    st.plotly_chart(px.scatter(filtered_df, x="cwe_id", y="cvss_score", color="severity", hover_data=["cve_id"], title="CVSS Score vs CWE ID"), use_container_width=True)

with tab3:
    timeline_df = filtered_df.groupby(filtered_df['published_date'].dt.to_period("M")).size().reset_index(name="count")
    timeline_df['published_date'] = timeline_df['published_date'].astype(str)
    st.plotly_chart(px.line(timeline_df, x="published_date", y="count", title="CVEs Over Time", markers=True), use_container_width=True)

with tab4:
    sunburst_df = filtered_df.dropna(subset=["cwe_id", "mitre_tactic", "mitre_technique_id"])
    st.plotly_chart(px.sunburst(sunburst_df, path=["cwe_id", "mitre_tactic", "mitre_technique_id"], title="CWE → Tactic → Technique"), use_container_width=True)
    
# Interactive Table
st.subheader("📋 Interactive CVE Table")
st.dataframe(filtered_df.sort_values(by="cvss_score", ascending=False), use_container_width=True)


# ⚙️ Conditional CVE Details
st.subheader("⚙️ Conditional CVE Details")

# Top 10 / All toggle
view_option = st.radio("View:", ["Top 10 Threats", "All Threats"], horizontal=True)

# CWE dropdown
selected_cwe = st.selectbox("Select CWE:", ["All"] + sorted(df["cwe_id"].dropna().unique()))

# Base filtering
details_df = filtered_df if selected_cwe == "All" else filtered_df[filtered_df["cwe_id"] == selected_cwe]

# Apply Top 10 filter if selected
if view_option == "Top 10 Threats":
    details_df = details_df.sort_values(by='cvss_score', ascending=False).head(10)

# Show expander blocks
for _, row in details_df.iterrows():
    with st.expander(f"{row['cve_id']} - {row['severity']} (CVSS {row['cvss_score']})"):
        st.write(f"**Description**: {row['description']}")
        st.write(f"**MITRE Technique**: {row['mitre_technique_id']}")
        st.write(f"**Tactic**: {row['mitre_tactic']}")
        st.write(f"**Published**: {row['published_date'].date()}")

# Optional: Summary stats
with st.expander("🔍 Threat Landscape Summary"):
    st.markdown(f"**Unique MITRE Tactics:** {filtered_df['mitre_tactic'].nunique()}")
    st.markdown(f"**Unique CVE IDs:** {filtered_df['cve_id'].nunique()}")
    st.markdown(f"**Severities in View:** {', '.join(details_df['severity'].dropna().unique())}")
    st.markdown(f"**Date Range:** {filtered_df['published_date'].min().date()} to {filtered_df['published_date'].max().date()}")


# Deployment Instructions
with st.expander("🚀 Deployment Instructions"):
    st.markdown("""
    ### Deploy on Streamlit Cloud
    1. Push this script and `CVE_MITRE_Mappings.csv` to a GitHub repo.
    2. Add a `requirements.txt` file with:
        ```
        streamlit
        pandas
        plotly
        ```
    3. Go to [https://streamlit.io/cloud](https://streamlit.io/cloud) and connect your repo.
    4. Select this script and deploy.
    """)
