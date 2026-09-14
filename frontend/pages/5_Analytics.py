import streamlit as st
import pandas as pd
import plotly.express as px
from utils import inject_css, load_data

inject_css()

st.markdown('<div class="soc-header">Advanced Security Analytics</div>', unsafe_allow_html=True)

df = load_data()
if df.empty:
    st.info("No security events available for analysis.")
    st.stop()

# ── Global Filters ──
with st.expander("🔍 Analytics Filters", expanded=False):
    f1, f2, f3 = st.columns(3)
    with f1:
        time_range = st.selectbox("Time Range", ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"], index=3)
    with f2:
        data_src = st.selectbox("Data Source", ["All", "Live AWS Only", "Demo/Simulation Only"])
    with f3:
        anom_only = st.checkbox("Show Anomalies Only", value=False)

# Apply global filters
filtered_df = df.copy()

if data_src == "Live AWS Only":
    filtered_df = filtered_df[filtered_df['is_demo'] == False]
elif data_src == "Demo/Simulation Only":
    filtered_df = filtered_df[filtered_df['is_demo'] == True]

if anom_only:
    filtered_df = filtered_df[filtered_df['isAnomaly'] == True]

# Note: Time filter logic would ideally use datetime comparisons. For simplicity, we just use the filtered_df.
if filtered_df.empty:
    st.success("No data matches the selected filters.")
    st.stop()

# ── Row 1: Timeline & Top APIs ──
c1, c2 = st.columns([2, 1])
with c1:
    fig_time = px.histogram(
        filtered_df, 
        x="timestamp", 
        color="severity",
        title="Incident Timeline by Severity",
        color_discrete_map={'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#eab308', 'Low': '#10b981', 'Unknown': '#4b5563'},
        nbins=50
    )
    fig_time.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig_time, use_container_width=True)

with c2:
    top_apis = filtered_df['eventName'].value_counts().reset_index().head(10)
    top_apis.columns = ['eventName', 'count']
    fig_api = px.bar(
        top_apis, 
        y="eventName", 
        x="count", 
        orientation='h', 
        title="Top 10 Suspicious APIs",
        color="count",
        color_continuous_scale="Reds"
    )
    fig_api.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", yaxis={'categoryorder':'total ascending'}, height=350, showlegend=False)
    st.plotly_chart(fig_api, use_container_width=True)

# ── Row 2: MITRE & Region ──
c3, c4 = st.columns(2)
with c3:
    mitre_df = filtered_df[filtered_df['mitre_name'] != 'N/A']['mitre_name'].value_counts().reset_index()
    mitre_df.columns = ['mitre_name', 'count']
    fig_mitre = px.pie(mitre_df, names="mitre_name", values="count", title="MITRE ATT&CK Distribution", hole=0.4, color_discrete_sequence=px.colors.sequential.Plasma)
    fig_mitre.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig_mitre, use_container_width=True)

with c4:
    reg_df = filtered_df['awsRegion'].value_counts().reset_index()
    reg_df.columns = ['awsRegion', 'count']
    fig_reg = px.bar(reg_df, x="awsRegion", y="count", title="Geographic Distribution (AWS Regions)", color="awsRegion", color_discrete_sequence=px.colors.qualitative.Pastel)
    fig_reg.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig_reg, use_container_width=True)

# ── Row 3: Principals & Remediation ──
c5, c6 = st.columns([1, 1])
with c5:
    princ_df = filtered_df['userIdentitytype'].value_counts().reset_index()
    princ_df.columns = ['userIdentitytype', 'count']
    fig_princ = px.bar(princ_df, x="userIdentitytype", y="count", title="Affected IAM Principals", color="count", color_continuous_scale="Blues")
    fig_princ.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig_princ, use_container_width=True)

with c6:
    rem_df = filtered_df['remediation_status'].value_counts().reset_index()
    rem_df.columns = ['remediation_status', 'count']
    color_map = {"PENDING_APPROVAL": "#eab308", "APPROVED": "#10b981", "ENFORCED": "#10b981", "NOT_REQUIRED": "#4b5563", "SIMULATED": "#8b5cf6", "BLOCKED": "#ef4444"}
    fig_rem = px.pie(rem_df, names="remediation_status", values="count", title="Remediation Status Distribution", color="remediation_status", color_discrete_map=color_map, hole=0.4)
    fig_rem.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig_rem, use_container_width=True)

# ── Row 4: Scatter Plot Risk vs Severity ──
st.markdown("### Risk vs Severity Analysis")
filtered_df['isAnomaly_str'] = filtered_df['isAnomaly'].apply(lambda x: "Anomaly" if x else "Normal")
fig_scatter = px.box(
    filtered_df,
    x="severity",
    y="riskScore",
    color="isAnomaly_str",
    title="Risk Score Spread by Severity & Anomaly Status",
    color_discrete_map={"Anomaly": "#ef4444", "Normal": "#3b82f6"}
)
fig_scatter.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=400)
st.plotly_chart(fig_scatter, use_container_width=True)
